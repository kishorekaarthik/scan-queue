package dev.scanqueue.storage;

import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Component;

/** Every role except the sender touches MinIO; the sender only needs Postgres and the webhook. */
@Component
@Profile("!sender")
class BucketInitializer implements ApplicationRunner {

    private final ObjectStore store;

    BucketInitializer(ObjectStore store) {
        this.store = store;
    }

    @Override
    public void run(ApplicationArguments args) {
        store.ensureBucket();
    }
}
