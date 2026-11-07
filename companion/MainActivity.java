package app.quantusnode.depin;

import android.Manifest;
import android.app.Activity;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.view.View;
import android.view.ViewGroup;
import android.view.WindowInsets;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;
import android.widget.Toast;

import java.io.File;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * Minimal single-screen UI, in the sibling apps' programmatic
 * style. Deliberately no settings: participation is meant to be
 * "install -> start node -> turn participation on", and every
 * parameter of the proof format is fixed by the SPEC, so there is
 * nothing here for the user to tune.
 *
 * Shows: observation state, this device's DePIN identity, the
 * node's peer id (once observed), the last checkpoint, and the
 * journal size. Actions: start / stop observation, export the
 * proof bundle (save to a file, or share it when small enough).
 */
public class MainActivity extends Activity {
    private static final int REQ_CREATE_DOCUMENT = 1001;
    private static final int REQ_NOTIFICATIONS = 1002;
    private static final int SHARE_TEXT_LIMIT_BYTES = 400 * 1024;
    /** Export cap (audit M-04, partial): a bundle holds at most
     *  this many checkpoints; beyond it the export is REFUSED
     *  with the reason shown. Splitting a long history into
     *  multiple chain-valid bundles is future work (see the v0.4
     *  progress memo). Until v0.6 the status text claimed the
     *  export was "limited to the most recent" ones while the
     *  code actually truncated and then failed its own
     *  self-check; the v0.6 re-audit flagged the mismatch, and
     *  refusal-with-reason is what the SPEC asks for. */
    static final int EXPORT_MAX_CHECKPOINTS = 100_000;

    private TextView statusView;
    private Button startButton;
    private Button stopButton;
    private final Handler refresher = new Handler(Looper.getMainLooper());
    // The pending export payload is NOT held here (F-10): an
    // Activity instance field dies with the instance when the
    // Activity is recreated while the document picker is open.
    // It lives in PendingExport (application scope) instead.
    /** Most recent entry of the persistent error log, re-read on
     *  create/resume so a failure from a previous (dead) process is
     *  still visible — and shareable — after relaunch. */
    private String persistedErrorEntry;

    private final Runnable refreshLoop = new Runnable() {
        @Override
        public void run() {
            refresh();
            refresher.postDelayed(this, 2000);
        }
    };

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        buildUi();
        if (Build.VERSION.SDK_INT >= 33
                && checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS)
                != PackageManager.PERMISSION_GRANTED) {
            requestPermissions(
                    new String[]{Manifest.permission.POST_NOTIFICATIONS},
                    REQ_NOTIFICATIONS);
        }
        // Start journal construction on the runtime's background
        // thread (M-07): the load re-verifies every entry of a
        // possibly long history and must not run on this main
        // thread. refresh() shows a preparing state until the
        // store is ready; recovery (quarantine) and failure then
        // surface there, as they did when this call blocked.
        CompanionRuntime.prefetchJournal(this);
        persistedErrorEntry = CompanionRuntime.lastErrorEntry(this);
    }

    @Override
    protected void onResume() {
        super.onResume();
        persistedErrorEntry = CompanionRuntime.lastErrorEntry(this);
        refreshLoop.run();
    }

    @Override
    protected void onPause() {
        refresher.removeCallbacks(refreshLoop);
        super.onPause();
    }

    private void buildUi() {
        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        int pad = dp(16);
        root.setPadding(pad, pad, pad, pad);
        root.setOnApplyWindowInsetsListener((v, insets) -> {
            android.graphics.Insets bars = insets.getInsets(
                    WindowInsets.Type.systemBars() | WindowInsets.Type.displayCutout());
            v.setPadding(pad + bars.left, pad + bars.top,
                    pad + bars.right, pad + bars.bottom);
            return insets;
        });

        TextView title = new TextView(this);
        title.setText("Quantus DePIN Companion");
        title.setTextSize(20);
        root.addView(title);

        TextView sub = new TextView(this);
        sub.setText("Quantus Node の観測コンパニオン（試作 / SPEC v0.5）\n"
                + "ノードのローカルRPCを読み、600秒ごとに署名付きチェックポイントを記録します。");
        sub.setTextSize(13);
        root.addView(sub);

        statusView = new TextView(this);
        statusView.setTextSize(14);
        LinearLayout.LayoutParams sp = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT);
        sp.topMargin = dp(12);
        statusView.setLayoutParams(sp);
        root.addView(statusView);

        startButton = new Button(this);
        startButton.setText("観測を開始");
        startButton.setOnClickListener(v -> {
            // Immediate feedback: the service confirms asynchronously,
            // and a dead-silent button reads as a hang (or worse, the
            // tap seems lost). The service clears startRequestedUnix
            // once it is running or has failed.
            CompanionStatus.startRequestedUnix = System.currentTimeMillis() / 1000L;
            statusView.setText("開始処理中…");
            startButton.setEnabled(false);
            try {
                Intent i = new Intent(this, ObservationService.class);
                i.setAction(ObservationService.ACTION_START);
                startForegroundService(i);
            } catch (Throwable t) {
                CompanionStatus.startRequestedUnix = 0;
                CompanionStatus.lastError = "サービスを開始できません: " + t.getMessage();
                CompanionRuntime.recordError(this, "start_request", t);
                refresh();
            }
        });
        root.addView(startButton);

        stopButton = new Button(this);
        stopButton.setText("観測を停止");
        stopButton.setOnClickListener(v -> {
            Intent i = new Intent(this, ObservationService.class);
            i.setAction(ObservationService.ACTION_STOP);
            startService(i);
        });
        root.addView(stopButton);

        Button saveButton = new Button(this);
        saveButton.setText("証明バンドルを書き出す（ファイル保存）");
        saveButton.setOnClickListener(v -> exportToFile());
        root.addView(saveButton);

        Button shareButton = new Button(this);
        shareButton.setText("証明バンドルを共有");
        shareButton.setOnClickListener(v -> shareBundle());
        root.addView(shareButton);

        Button errorShareButton = new Button(this);
        errorShareButton.setText("記録されたエラーを共有");
        errorShareButton.setOnClickListener(v -> shareErrorLog());
        root.addView(errorShareButton);

        ScrollView scroll = new ScrollView(this);
        scroll.addView(root);
        setContentView(scroll);
    }

    private void refresh() {
        // M-07: never block the UI thread on the journal. While
        // construction is in flight the screen shows a preparing
        // state; a construction failure is named exactly as
        // before (journalError / identityError channels).
        JournalStore journal = CompanionRuntime.journalIfReady();
        boolean starting = CompanionStatus.startRequestedUnix > 0
                && !CompanionStatus.serviceRunning;
        StringBuilder sb = new StringBuilder();
        sb.append("観測状態: ").append(
                CompanionStatus.serviceRunning ? "実行中"
                        : starting ? "開始処理中…" : "停止中").append('\n');
        if (journal == null) {
            IllegalStateException failure = CompanionRuntime.journalFailure();
            if (failure != null) {
                sb.append("ジャーナルを開けません: ")
                        .append(failure.getMessage()).append('\n');
            } else {
                sb.append("ジャーナルを準備しています…\n");
            }
            if (CompanionStatus.identityError != null) {
                sb.append("ID鍵の準備に失敗: ")
                        .append(CompanionStatus.identityError).append('\n');
            }
            if (CompanionStatus.lastError != null) {
                sb.append("直近の状態: ")
                        .append(CompanionStatus.lastError).append('\n');
            }
            statusView.setText(sb.toString());
            startButton.setEnabled(!CompanionStatus.serviceRunning
                    && CompanionStatus.startRequestedUnix == 0);
            stopButton.setEnabled(CompanionStatus.serviceRunning);
            return;
        }
        if (starting
                && CompanionRuntime.journalReady()
                && System.currentTimeMillis() / 1000L
                        - CompanionStatus.startRequestedUnix > 20) {
            sb.append("開始が完了しません。下の記録エラーを確認してください\n");
        }
        if (CompanionStatus.identityError != null) {
            sb.append("ID鍵の準備に失敗: ")
                    .append(CompanionStatus.identityError).append('\n');
        }
        String deviceId = CompanionStatus.deviceId;
        sb.append("デバイスID: ").append(deviceId == null ? "（未生成）" : deviceId).append('\n');
        sb.append("ノードのピアID: ").append(
                CompanionStatus.nodePeerId == null
                        ? "（未取得）" : CompanionStatus.nodePeerId).append('\n');
        sb.append("蓄積チェックポイント: ").append(journal.count()).append(" 件\n");
        if (journal.droppedOnLoad() > 0) {
            // Journal entries that failed signature / consistency
            // verification at load were dropped (H-04); say so
            // plainly instead of silently continuing on a shortened
            // history.
            sb.append("ジャーナル検証で破棄されたエントリ: ")
                    .append(journal.droppedOnLoad())
                    .append(" 件（改ざん・破損の可能性があります）\n");
        }
        if (journal.recoveryOccurred()) {
            // Journal / archive header recovery (B4): a damaged
            // file was quarantined — bytes preserved under the
            // name shown — and recording restarted on a fresh
            // journal under this device's identity. Name the
            // quarantined file(s) plainly, like the other journal
            // notices.
            StringBuilder names = new StringBuilder();
            for (File q : journal.quarantinedFiles()) {
                if (names.length() > 0) names.append("、");
                names.append(q.getName());
            }
            sb.append("破損したジャーナルを隔離しました（内容は隔離ファイルに保持されています）: ")
                    .append(names).append('\n');
            sb.append("新しいジャーナルで記録を再開しています\n");
        }
        JournalStore.HoldInfo hold = journal.holdInfo();
        if (hold != null) {
            // Accumulation hold (M-02, v0.8): the live RPC view
            // disagrees with the recorded tail, so checkpoints
            // are being held — the recorded history itself is
            // untouched (v0.8 removed the v0.7 segment
            // preservation: RPC disagreement never sets signed
            // history aside). The hold state is persisted by the
            // journal, so this notice is shown straight from the
            // store and stays true across process restarts;
            // appending resumes by itself when the node's best
            // catches up with the recorded tail.
            sb.append("ノードの応答が記録済みの履歴と食い違うため、チェックポイントを保留しています")
                    .append("（記録済み best ").append(hold.tailBest)
                    .append(" / 現在の応答 best ").append(hold.liveBest)
                    .append("、保留開始 ").append(formatDateTime(hold.sinceUnix))
                    .append("）\n");
            sb.append("応答が履歴に追いつけば自動で再開します。記録済みの履歴はそのまま保持されています\n");
        }
        if (journal.partialTailDropped() > 0) {
            // An append interrupted mid-line (process killed while
            // writing) left an unterminated tail, truncated on
            // open (R-M04). Say so plainly: the partial line was
            // never a complete entry, but the repair should not be
            // silent either.
            sb.append("書き込み途中で途切れたジャーナル末尾を切り捨てました: ")
                    .append(journal.partialTailDropped()).append(" 件\n");
        }
        if (journal.archivedCount() > 0) {
            // Legacy entries are NOT dropped: they are preserved
            // in per-format archive files (they cannot join the
            // live v0.5 chain — their hashes are bound to their own
            // format domains — but the records themselves are
            // kept). Report each archive's count distinctly from
            // the dropped count above.
            StringBuilder arc = new StringBuilder("旧形式の記録をアーカイブとして保持しています");
            boolean first = true;
            if (journal.archivedV04Count() > 0) {
                arc.append(first ? "（" : "、").append("v0.4形式 ")
                        .append(journal.archivedV04Count()).append(" 件");
                first = false;
            }
            if (journal.archivedV03Count() > 0) {
                arc.append(first ? "（" : "、").append("v0.3形式 ")
                        .append(journal.archivedV03Count()).append(" 件");
                first = false;
            }
            if (!first) arc.append("）");
            sb.append(arc).append('\n');
        }
        if (journal.count() > EXPORT_MAX_CHECKPOINTS) {
            sb.append("蓄積が書き出し上限の ").append(EXPORT_MAX_CHECKPOINTS)
                    .append(" 件を超えているため、証明バンドルを書き出せません")
                    .append("（現在 ").append(journal.count()).append(" 件）\n");
        }
        if (CompanionStatus.lastCheckpointUnix > 0) {
            sb.append("最終チェックポイント: ")
                    .append(formatDateTime(CompanionStatus.lastCheckpointUnix)).append('\n');
            sb.append("best ").append(CompanionStatus.lastBest)
                    .append(" / finalized ").append(CompanionStatus.lastFinalized)
                    .append(" / ピア ").append(CompanionStatus.lastPeers).append('\n');
        } else {
            sb.append("最終チェックポイント: まだありません\n");
        }
        if (CompanionStatus.lastError != null) {
            sb.append("直近の状態: ").append(CompanionStatus.lastError).append('\n');
        }
        if (persistedErrorEntry != null) {
            sb.append("\n前回記録されたエラー:\n")
                    .append(persistedErrorEntry).append('\n');
        }
        statusView.setText(sb.toString());
        startButton.setEnabled(!CompanionStatus.serviceRunning
                && CompanionStatus.startRequestedUnix == 0);
        stopButton.setEnabled(CompanionStatus.serviceRunning);
    }

    private void shareErrorLog() {
        String log = CompanionRuntime.errorLog(this);
        if (log == null || log.isEmpty()) {
            toast("記録されたエラーはありません");
            return;
        }
        Intent i = new Intent(Intent.ACTION_SEND);
        i.setType("text/plain");
        i.putExtra(Intent.EXTRA_SUBJECT, "DePIN Companion error log");
        i.putExtra(Intent.EXTRA_TEXT, log);
        startActivity(Intent.createChooser(i, "記録されたエラーを共有"));
    }

    // ---------------- bundle export ----------------
    //
    // Building, signing and self-checking a bundle over a long
    // journal is not UI-thread work (audit M-04): both export
    // paths run it on a background thread and only the resulting
    // intents / toasts come back to the UI thread.

    private Map<String, Object> buildCurrentBundle() throws Exception {
        JournalStore journal = CompanionRuntime.journal(this);
        List<DepinCore.Checkpoint> all = journal.checkpoints();
        if (all.isEmpty()) {
            return null;
        }
        // Export cap: beyond EXPORT_MAX_CHECKPOINTS the export is
        // REFUSED with the reason (see the constant). Until v0.6
        // this truncated to the most recent checkpoints — a chain
        // fragment that then failed the self-check below — while
        // the status text claimed the export was merely "limited";
        // the v0.6 re-audit flagged the mismatch.
        if (all.size() > EXPORT_MAX_CHECKPOINTS) {
            throw new IllegalStateException(
                    "チェックポイントが書き出し上限 "
                            + EXPORT_MAX_CHECKPOINTS + " 件を超えています（現在 "
                            + all.size() + " 件）");
        }
        List<DepinCore.Checkpoint> cps = all;
        AndroidSeedVault vault = new AndroidSeedVault(this);
        byte[] seed = vault.loadOrCreateSeed();
        try {
            long created = System.currentTimeMillis() / 1000L;
            Map<String, Object> bundle = DepinCore.assembleBundle(
                    seed, cps, created, DepinCore.PRODUCTION_ITERATIONS);
            // Self-check before anything leaves the app: signature
            // and checkpoint hashes must verify under our own port
            // of the reference rules. The expensive chain
            // recomputation is the verifier's job (exercised
            // against the reference in tests); it is skipped here
            // so export stays fast even with a long journal.
            List<String> errors = DepinCore.verifyBundle(
                    bundle, DepinCore.PRODUCTION_ITERATIONS, false);
            if (!errors.isEmpty()) {
                throw new IllegalStateException(
                        "自己検証に失敗しました: " + errors.get(0));
            }
            return bundle;
        } finally {
            // L-01 / R-L01: the export path loads the seed on
            // demand (the vault caches nothing) and its copy is
            // zeroed as soon as the bundle is signed.
            java.util.Arrays.fill(seed, (byte) 0);
            vault.lock();
        }
    }

    private interface BundleReady {
        void onBundle(String json);
    }

    /** Build + serialize the current bundle off the UI thread. */
    private void buildBundleAsync(String failurePrefix, BundleReady ready) {
        new Thread(() -> {
            try {
                Map<String, Object> bundle = buildCurrentBundle();
                if (bundle == null) {
                    runOnUiThread(() -> toast("チェックポイントがまだありません"));
                    return;
                }
                // buildCurrentBundle() has already self-checked the
                // bundle (signature + checkpoint hashes).
                String json = Json.pretty(bundle);
                runOnUiThread(() -> ready.onBundle(json));
            } catch (Exception e) {
                runOnUiThread(() -> toast(failurePrefix + ": " + e.getMessage()));
            }
        }, "depin-bundle-build").start();
    }

    private void exportToFile() {
        buildBundleAsync("書き出しに失敗", json -> {
            PendingExport.set(json);
            Intent i = new Intent(Intent.ACTION_CREATE_DOCUMENT);
            i.addCategory(Intent.CATEGORY_OPENABLE);
            i.setType("application/json");
            i.putExtra(Intent.EXTRA_TITLE, suggestFileName());
            startActivityForResult(i, REQ_CREATE_DOCUMENT);
        });
    }

    private void shareBundle() {
        buildBundleAsync("共有に失敗", json -> {
            if (json.getBytes(StandardCharsets.UTF_8).length > SHARE_TEXT_LIMIT_BYTES) {
                toast("バンドルが大きいため共有できません。ファイル保存を使ってください");
                return;
            }
            Intent i = new Intent(Intent.ACTION_SEND);
            i.setType("text/plain");
            i.putExtra(Intent.EXTRA_SUBJECT, suggestFileName());
            i.putExtra(Intent.EXTRA_TEXT, json);
            startActivity(Intent.createChooser(i, "証明バンドルを共有"));
        });
    }

    private String suggestFileName() {
        String id = CompanionStatus.deviceId;
        String shortId = (id == null) ? "device" : id.substring(5, Math.min(17, id.length()));
        String date = new SimpleDateFormat("yyyyMMdd-HHmmss", Locale.US)
                .format(new Date());
        return "depin-bundle-" + shortId + "-" + date + ".json";
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        if (requestCode != REQ_CREATE_DOCUMENT) {
            return;
        }
        if (resultCode != RESULT_OK || data == null || data.getData() == null) {
            PendingExport.clear();
            return;
        }
        Uri uri = data.getData();
        // Take (read + clear) from the application-scoped holder:
        // it survived any recreation of this Activity while the
        // picker was open (F-10). A null here means the process
        // itself was restarted mid-export; say so WITHOUT opening
        // the destination, so no empty file is left behind.
        String json = PendingExport.take();
        if (json == null) {
            toast("保存に失敗: 書き出し内容が失われました。もう一度書き出してください");
            return;
        }
        new Thread(() -> {
            try (OutputStream out = getContentResolver().openOutputStream(uri)) {
                if (out == null) throw new IllegalStateException("no output stream");
                out.write(json.getBytes(StandardCharsets.UTF_8));
                runOnUiThread(() -> toast("バンドルを保存しました"));
            } catch (Exception e) {
                runOnUiThread(() -> toast("保存に失敗: " + e.getMessage()));
            }
        }, "depin-export").start();
    }

    // ---------------- helpers ----------------

    private int dp(int value) {
        return Math.round(value * getResources().getDisplayMetrics().density);
    }

    private void toast(String msg) {
        Toast.makeText(this, msg, Toast.LENGTH_LONG).show();
    }

    private static String formatDateTime(long unix) {
        return new SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.US)
                .format(new Date(unix * 1000L));
    }

    // Referenced so the field is not stripped from status reads.
    @SuppressWarnings("unused")
    private View unusedAnchor() {
        return statusView;
    }
}
