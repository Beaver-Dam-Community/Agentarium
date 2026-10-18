-- Do not erase durable pending work on rollback. The preceding schema migration
-- removes the queue; reinstallation re-enqueues all retained evidence.
SELECT 1;
