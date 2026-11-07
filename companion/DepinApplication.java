package app.quantusnode.depin;

import android.app.Application;

/**
 * Installs the process-wide uncaught-exception recorder. The
 * handler writes the failure to the persistent CrashLog (class,
 * message, top stack frames — never key material) and then chains
 * to the previously installed handler, so the platform's normal
 * crash behaviour is unchanged; the only difference is that the
 * next launch can show and share what happened.
 */
public class DepinApplication extends Application {
    @Override
    public void onCreate() {
        super.onCreate();
        Thread.UncaughtExceptionHandler previous =
                Thread.getDefaultUncaughtExceptionHandler();
        Thread.setDefaultUncaughtExceptionHandler((thread, error) -> {
            try {
                CrashLog.record(getFilesDir(), "uncaught", error);
            } catch (Throwable ignored) {
                // The recorder must never mask the original crash.
            }
            if (previous != null) {
                previous.uncaughtException(thread, error);
            }
        });
    }
}
