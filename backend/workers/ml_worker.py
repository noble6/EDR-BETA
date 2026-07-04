import asyncio
import json
from datetime import datetime

import structlog
import aio_pika
from tenacity import retry, stop_after_attempt, wait_exponential
from sqlalchemy import select

# Adjusts Python path to import correctly
import sys
from pathlib import Path
sys.path.append(str(Path(__file__).resolve().parent.parent))

from core.config import settings
from services.ml_inference import evaluate_risk
from services.reputation import classify_risk, compute_confidence
from core.cache import cache_client
from db.models import TaskStatus, Reputation, FileMetadata
from db.session import AsyncSessionLocal

# Standardize JSON logger
structlog.configure(
    processors=[
        structlog.stdlib.add_log_level,
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.JSONRenderer()
    ]
)
logger = structlog.get_logger()

async def persist_reputation(task_id: str, sha256: str, inference: dict) -> None:
    async with AsyncSessionLocal() as session:
        rep_stmt = select(Reputation).where(Reputation.sha256 == sha256)
        rep_obj = (await session.execute(rep_stmt)).scalar_one_or_none()

        now = datetime.utcnow()
        if rep_obj is None:
            rep_obj = Reputation(
                sha256=sha256,
                first_seen=now,
                last_seen=now,
                frequency=1,
                risk_score=float(inference["risk_score"]),
                confidence_score=float(inference["risk_score"]),
                classification=inference["classification"],
                is_malicious=inference["classification"] == "malicious",
            )
            session.add(rep_obj)
        else:
            previous_last_seen = rep_obj.last_seen
            rep_obj.frequency = int(rep_obj.frequency or 0) + 1
            rep_obj.last_seen = now
            rep_obj.risk_score = float(inference["risk_score"])
            rep_obj.classification = classify_risk(rep_obj.risk_score, rep_obj.frequency)
            rep_obj.is_malicious = rep_obj.classification == "malicious"
            rep_obj.confidence_score = compute_confidence(
                previous_confidence=float(rep_obj.confidence_score or 0.0),
                risk_score=rep_obj.risk_score,
                frequency=rep_obj.frequency,
                last_seen=previous_last_seen,
            )

        file_stmt = select(FileMetadata).where(FileMetadata.task_id == task_id)
        file_obj = (await session.execute(file_stmt)).scalar_one_or_none()
        if file_obj is not None:
            file_obj.status = TaskStatus.COMPLETED

        await session.commit()

    verdict_cache = {
        "sha256": sha256,
        "classification": rep_obj.classification,
        "is_malicious": bool(rep_obj.is_malicious),
        "risk_score": float(rep_obj.risk_score),
        "confidence_score": float(rep_obj.confidence_score),
        "frequency": int(rep_obj.frequency),
        "first_seen": rep_obj.first_seen.isoformat() if rep_obj.first_seen else None,
        "last_seen": rep_obj.last_seen.isoformat() if rep_obj.last_seen else None,
    }
    await cache_client.set_json(f"hash:{sha256}", verdict_cache, ttl_seconds=24 * 3600)

    logger.info(
        "reputation_updated",
        task_id=task_id,
        sha256=sha256,
        classification=verdict_cache["classification"],
        risk_score=verdict_cache["risk_score"],
        confidence_score=verdict_cache["confidence_score"],
        frequency=verdict_cache["frequency"],
    )


async def mark_task_failed(task_id: str) -> None:
    async with AsyncSessionLocal() as session:
        file_stmt = select(FileMetadata).where(FileMetadata.task_id == task_id)
        file_obj = (await session.execute(file_stmt)).scalar_one_or_none()
        if file_obj is not None:
            file_obj.status = TaskStatus.FAILED
            await session.commit()

@retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=2, max=10))
async def process_inference(payload: dict):
    """Executes ML inference logic safely within bound retries."""
    task_id = payload.get("task_id")
    sha256 = payload.get("sha256")
    static_features = payload.get("static_results", {})
    
    if not isinstance(static_features, dict):
        raise ValueError(f"Invalid static_results format in payload for {task_id}")

    try:
        # 1. Run Machine Learning Evaluation
        # Since sklearn models use numpy arrays internally, they are mostly CPU bound.
        # For huge loads, use asyncio.to_thread / run_in_executor
        inference = await asyncio.to_thread(evaluate_risk, static_features)

        # 2. Update the Threat Intelligence DB Base and cache
        await persist_reputation(task_id=task_id, sha256=sha256, inference=inference)

        # 3. Dynamic Sandbox Forwarding
        # If the risk score is suspicious (e.g. > 40.0 but < 90.0) we should 
        # force a dynamic run to confirm if it evades static detection.
        if 40.0 < inference["risk_score"] < 90.0:
            logger.info("sandbox_trigger", task_id=task_id, sha256=sha256, risk=inference["risk_score"])
            # Push to sandbox-queue via RabbitMQ
            connection = await aio_pika.connect_robust(settings.RABBITMQ_URL)
            async with connection:
                channel = await connection.channel()
                await channel.default_exchange.publish(
                    aio_pika.Message(body=json.dumps({
                        "task_id": task_id,
                        "file_hash": sha256
                    }).encode()),
                    routing_key="sandbox-queue",
                )

        
        # 3. Future hook -> if is_malicious and Sandbox exists, push to `sandbox-queue`
        if inference["classification"] == "malicious":
            logger.info("routing_to_sandbox", task_id=task_id, reason="high_risk_score")
            # publish_task("sandbox-queue", ...)
        elif inference["classification"] == "suspicious":
            logger.info("suspicious_classification", task_id=task_id, reason="threshold_window")

    except Exception as e:
        logger.error("ml_pipeline_error", task_id=task_id, error=str(e))
        if task_id:
            await mark_task_failed(task_id)
        raise e

async def consume_ml_messages():
    """RabbitMQ consumer loop for ML events."""
    logger.info("starting_ml_worker", queue="ml-inference-queue")
    
    try:
        connection = await aio_pika.connect_robust(settings.RABBITMQ_URL)
        async with connection:
            channel = await connection.channel()
            # Protect Memory limit
            await channel.set_qos(prefetch_count=10)
            
            queue = await channel.declare_queue("ml-inference-queue", durable=True)
            
            async with queue.iterator() as queue_iter:
                async for message in queue_iter:
                    async with message.process(ignore_action_exceptions=True):
                        try:
                            payload = json.loads(message.body.decode())
                            logger.info("ml_message_received", task_id=payload.get("task_id"))
                            
                            # Execute Inference
                            await process_inference(payload)
                            
                        except Exception as e:
                            logger.error("ml_message_abandoned", error=str(e))
                            
    except Exception as connection_error:
        logger.error("rabbitmq_connection_failed", error=str(connection_error))
        raise

if __name__ == "__main__":
    try:
        asyncio.run(consume_ml_messages())
    except KeyboardInterrupt:
        logger.info("ml_worker_shutdown_requested")
