-- The mock webhook keeps its dedup table in its own database, as a real
-- third-party receiver would. Runs once, on a fresh Postgres volume.
CREATE DATABASE webhook;
