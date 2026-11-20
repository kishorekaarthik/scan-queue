package dev.scanqueue.job;

public enum JobStatus {
    /** Waiting to be claimed (new, or returned after an expired lease / failed attempt). */
    QUEUED,
    /** Claimed by a worker that holds an unexpired lease. */
    RUNNING,
    /** Verdict saved. Terminal. */
    DONE,
    /** Failed max_attempts times. Terminal; needs a human. */
    DEAD
}
