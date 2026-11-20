package dev.scanqueue.storage;

import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.stereotype.Component;

@Component
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
