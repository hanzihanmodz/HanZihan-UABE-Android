package com.hanzihan.uabe;

import android.app.Activity;
import android.content.Intent;
import android.graphics.Color;
import android.graphics.Typeface;
import android.net.Uri;
import android.os.Bundle;
import android.view.Gravity;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;
import android.widget.Toast;

import com.chaquo.python.PyObject;
import com.chaquo.python.Python;
import com.chaquo.python.android.AndroidPlatform;

import org.json.JSONObject;

import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class MainActivity extends Activity {
    private static final int PICK_FILE = 1001;
    private static final int SAVE_TXT = 1002;
    private static final int SAVE_JSON = 1003;
    private static final int SAVE_EDITED = 1004;
    private final ExecutorService worker = Executors.newSingleThreadExecutor();
    private TextView status;
    private TextView reportView;
    private Button analyzeButton;
    private Button saveTxtButton;
    private Button saveJsonButton;
    private Button applyEditButton;
    private Button saveEditedButton;
    private Button probeUnityButton;
    private TextView unityProbeView;
    private EditText oldTextInput;
    private EditText newTextInput;
    private File editedFile;
    private File selectedFile;
    private File txtReport;
    private File jsonReport;

    private final int bg = Color.rgb(8, 10, 15);
    private final int panel = Color.rgb(18, 22, 31);
    private final int red = Color.rgb(218, 43, 69);
    private final int white = Color.rgb(239, 241, 247);
    private final int muted = Color.rgb(151, 159, 176);

    @Override public void onCreate(Bundle state) {
        super.onCreate(state);
        getWindow().setStatusBarColor(bg);
        getWindow().setNavigationBarColor(bg);
        getWindow().getDecorView().setSystemUiVisibility(0);
        if (!Python.isStarted()) Python.start(new AndroidPlatform(this));
        buildUi();
    }

    private void buildUi() {
        ScrollView scroll = new ScrollView(this);
        scroll.setFillViewport(true);
        scroll.setBackgroundColor(bg);
        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setPadding(dp(18), dp(24), dp(18), dp(32));
        scroll.addView(root);

        TextView brand = text("HANZIHAN UABE", 23, white, true);
        brand.setLetterSpacing(0.08f);
        root.addView(brand);
        TextView subtitle = text("ANDROID ASSET WORKSPACE", 10, muted, true);
        subtitle.setLetterSpacing(0.16f);
        LinearLayout.LayoutParams subLp = params(-2, -2); subLp.topMargin = dp(5);
        root.addView(subtitle, subLp);

        View line = new View(this); line.setBackgroundColor(red);
        LinearLayout.LayoutParams lineLp = params(dp(54), dp(3)); lineLp.topMargin = dp(18); lineLp.bottomMargin = dp(22);
        root.addView(line, lineLp);

        LinearLayout card = card();
        root.addView(card, params(-1, -2));
        card.addView(text("AOV BYTES ANALYZER", 16, white, true));
        TextView desc = text("Analisis file .bytes secara lokal. File sumber tidak diubah.", 12, muted, false);
        LinearLayout.LayoutParams descLp = params(-1, -2); descLp.topMargin = dp(8);
        card.addView(desc, descLp);

        Button choose = button("PILIH FILE", false);
        LinearLayout.LayoutParams chooseLp = params(-1, dp(48)); chooseLp.topMargin = dp(18);
        card.addView(choose, chooseLp);
        choose.setOnClickListener(v -> {
            Intent i = new Intent(Intent.ACTION_OPEN_DOCUMENT);
            i.addCategory(Intent.CATEGORY_OPENABLE);
            i.setType("*/*");
            startActivityForResult(i, PICK_FILE);
        });

        status = text("Belum ada file dipilih.", 12, muted, false);
        LinearLayout.LayoutParams statusLp = params(-1, -2); statusLp.topMargin = dp(12);
        card.addView(status, statusLp);

        analyzeButton = button("ANALISIS SEKARANG", true);
        LinearLayout.LayoutParams runLp = params(-1, dp(48)); runLp.topMargin = dp(12);
        card.addView(analyzeButton, runLp);
        analyzeButton.setEnabled(false);
        analyzeButton.setOnClickListener(v -> runAnalysis());

        LinearLayout resultCard = card();
        LinearLayout.LayoutParams resultLp = params(-1, -2); resultLp.topMargin = dp(18);
        root.addView(resultCard, resultLp);
        resultCard.addView(text("HASIL ANALISIS", 14, white, true));
        reportView = text("Laporan akan muncul di sini setelah analisis selesai.", 11, muted, false);
        reportView.setTypeface(Typeface.MONOSPACE);
        reportView.setTextIsSelectable(true);
        LinearLayout.LayoutParams reportLp = params(-1, -2); reportLp.topMargin = dp(12);
        resultCard.addView(reportView, reportLp);

        saveTxtButton = button("SIMPAN LAPORAN TXT", false);
        saveJsonButton = button("SIMPAN LAPORAN JSON", false);
        LinearLayout.LayoutParams saveLp = params(-1, dp(44)); saveLp.topMargin = dp(12);
        resultCard.addView(saveTxtButton, saveLp);
        LinearLayout.LayoutParams saveJsonLp = params(-1, dp(44)); saveJsonLp.topMargin = dp(8);
        resultCard.addView(saveJsonButton, saveJsonLp);
        saveTxtButton.setEnabled(false); saveJsonButton.setEnabled(false);
        saveTxtButton.setOnClickListener(v -> createSaveIntent(SAVE_TXT));
        saveJsonButton.setOnClickListener(v -> createSaveIntent(SAVE_JSON));

        LinearLayout editorCard = card();
        LinearLayout.LayoutParams editorLp = params(-1, -2); editorLp.topMargin = dp(18);
        root.addView(editorCard, editorLp);
        editorCard.addView(text("AOV TEXT EDITOR", 14, white, true));
        TextView editorNote = text("Penggantian byte UTF-8 secara langsung. File asli tidak ditimpa. Teks di dalam data terkompresi atau terenkripsi mungkin tidak ditemukan.", 11, muted, false);
        LinearLayout.LayoutParams editorNoteLp = params(-1, -2); editorNoteLp.topMargin = dp(8);
        editorCard.addView(editorNote, editorNoteLp);
        oldTextInput = new EditText(this);
        oldTextInput.setHint("TEKS ASLI YANG MAU DIGANTI");
        oldTextInput.setTextColor(white); oldTextInput.setHintTextColor(muted);
        oldTextInput.setTextSize(13); oldTextInput.setMinLines(2);
        oldTextInput.setGravity(Gravity.TOP | Gravity.START);
        oldTextInput.setBackgroundTintList(android.content.res.ColorStateList.valueOf(red));
        LinearLayout.LayoutParams oldLp = params(-1, -2); oldLp.topMargin = dp(12);
        editorCard.addView(oldTextInput, oldLp);
        newTextInput = new EditText(this);
        newTextInput.setHint("TEKS PENGGANTI");
        newTextInput.setTextColor(white); newTextInput.setHintTextColor(muted);
        newTextInput.setTextSize(13); newTextInput.setMinLines(2);
        newTextInput.setGravity(Gravity.TOP | Gravity.START);
        newTextInput.setBackgroundTintList(android.content.res.ColorStateList.valueOf(red));
        LinearLayout.LayoutParams newLp = params(-1, -2); newLp.topMargin = dp(8);
        editorCard.addView(newTextInput, newLp);
        applyEditButton = button("TERAPKAN PENGGANTIAN", true);
        LinearLayout.LayoutParams applyLp = params(-1, dp(46)); applyLp.topMargin = dp(12);
        editorCard.addView(applyEditButton, applyLp);
        applyEditButton.setEnabled(false);
        applyEditButton.setOnClickListener(v -> applyTextEdit());
        saveEditedButton = button("EKSPOR FILE HASIL EDIT", false);
        LinearLayout.LayoutParams editedLp = params(-1, dp(44)); editedLp.topMargin = dp(8);
        editorCard.addView(saveEditedButton, editedLp);
        saveEditedButton.setEnabled(false);
        saveEditedButton.setOnClickListener(v -> createSaveIntent(SAVE_EDITED));

        LinearLayout bytesCard = card();
        LinearLayout.LayoutParams bytesLp = params(-1, -2); bytesLp.topMargin = dp(18);
        root.addView(bytesCard, bytesLp);
        bytesCard.addView(text("BYTE OFFSET INSPECTOR", 14, white, true));
        TextView bytesNote = text("Lihat byte dalam format HEX dan ASCII. Pemeriksaan hanya membaca file dan dibatasi 4096 byte per permintaan.", 11, muted, false);
        LinearLayout.LayoutParams bytesNoteLp = params(-1, -2); bytesNoteLp.topMargin = dp(8);
        bytesCard.addView(bytesNote, bytesNoteLp);
        EditText offsetInput = new EditText(this);
        offsetInput.setSingleLine(true); offsetInput.setText("0"); offsetInput.setHint("OFFSET (contoh: 0 atau 0x100)");
        offsetInput.setTextColor(white); offsetInput.setHintTextColor(muted); offsetInput.setTextSize(13);
        offsetInput.setBackgroundTintList(android.content.res.ColorStateList.valueOf(red));
        LinearLayout.LayoutParams offsetLp = params(-1, -2); offsetLp.topMargin = dp(10);
        bytesCard.addView(offsetInput, offsetLp);
        EditText lengthInput = new EditText(this);
        lengthInput.setSingleLine(true); lengthInput.setText("256"); lengthInput.setHint("PANJANG BYTE (maks. 4096)");
        lengthInput.setTextColor(white); lengthInput.setHintTextColor(muted); lengthInput.setTextSize(13);
        lengthInput.setBackgroundTintList(android.content.res.ColorStateList.valueOf(red));
        LinearLayout.LayoutParams lengthLp = params(-1, -2); lengthLp.topMargin = dp(6);
        bytesCard.addView(lengthInput, lengthLp);
        Button inspectBytesButton = button("INSPEKSI BYTE", true);
        LinearLayout.LayoutParams inspectLp = params(-1, dp(44)); inspectLp.topMargin = dp(10);
        bytesCard.addView(inspectBytesButton, inspectLp);
        TextView bytesResult = text("Hasil HEX/ASCII akan tampil di sini.", 10, muted, false);
        bytesResult.setTypeface(Typeface.MONOSPACE); bytesResult.setTextIsSelectable(true);
        LinearLayout.LayoutParams bytesResultLp = params(-1, -2); bytesResultLp.topMargin = dp(10);
        bytesCard.addView(bytesResult, bytesResultLp);
        inspectBytesButton.setOnClickListener(v -> {
            if (selectedFile == null) { status.setText("Pilih file terlebih dahulu."); return; }
            inspectBytesButton.setEnabled(false);
            bytesResult.setText("Membaca byte...");
            worker.execute(() -> {
                try {
                    PyObject module = Python.getInstance().getModule("android_bridge");
                    String raw = module.callAttr("inspect_bytes", selectedFile.getAbsolutePath(),
                            offsetInput.getText().toString(), lengthInput.getText().toString()).toString();
                    JSONObject result = new JSONObject(raw);
                    String display = "File: " + result.getString("file_name") +
                            "\\nUkuran: " + result.getLong("file_size") +
                            " byte\\nOffset: 0x" + Long.toHexString(result.getLong("offset")).toUpperCase() +
                            "\\nDibaca: " + result.getInt("bytes_read") + " byte\\n\\n" +
                            result.getString("hex_dump");
                    runOnUiThread(() -> { bytesResult.setText(display); inspectBytesButton.setEnabled(true); });
                } catch (Exception e) {
                    runOnUiThread(() -> { bytesResult.setText("Gagal: " + e.getMessage()); inspectBytesButton.setEnabled(true); });
                }
            });
        });

        LinearLayout stringsCard = card();
        LinearLayout.LayoutParams stringsLp = params(-1, -2); stringsLp.topMargin = dp(18);
        root.addView(stringsCard, stringsLp);
        stringsCard.addView(text("ASCII STRING EXTRACTOR", 14, white, true));
        TextView stringsNote = text("Cari rangkaian teks ASCII yang terbaca dan tampilkan offset byte-nya. Hanya membaca file; maksimal 300 hasil, sesuai perilaku editor Flask lama.", 11, muted, false);
        LinearLayout.LayoutParams stringsNoteLp = params(-1, -2); stringsNoteLp.topMargin = dp(8);
        stringsCard.addView(stringsNote, stringsNoteLp);
        EditText minStringLength = new EditText(this);
        minStringLength.setSingleLine(true); minStringLength.setText("4");
        minStringLength.setHint("PANJANG MINIMUM (4–128)");
        minStringLength.setTextColor(white); minStringLength.setHintTextColor(muted); minStringLength.setTextSize(13);
        minStringLength.setBackgroundTintList(android.content.res.ColorStateList.valueOf(red));
        LinearLayout.LayoutParams minStringLp = params(-1, -2); minStringLp.topMargin = dp(8);
        stringsCard.addView(minStringLength, minStringLp);
        Button extractStringsButton = button("EKSTRAK STRING", true);
        LinearLayout.LayoutParams extractStringsLp = params(-1, dp(44)); extractStringsLp.topMargin = dp(10);
        stringsCard.addView(extractStringsButton, extractStringsLp);
        TextView stringsResult = text("Hasil string akan tampil di sini.", 10, muted, false);
        stringsResult.setTypeface(Typeface.MONOSPACE); stringsResult.setTextIsSelectable(true);
        LinearLayout.LayoutParams stringsResultLp = params(-1, -2); stringsResultLp.topMargin = dp(10);
        stringsCard.addView(stringsResult, stringsResultLp);
        extractStringsButton.setOnClickListener(v -> {
            if (selectedFile == null) { status.setText("Pilih file terlebih dahulu."); return; }
            extractStringsButton.setEnabled(false);
            stringsResult.setText("Mencari string ASCII...");
            worker.execute(() -> {
                try {
                    PyObject module = Python.getInstance().getModule("android_bridge");
                    String raw = module.callAttr("extract_ascii_strings", selectedFile.getAbsolutePath(),
                            minStringLength.getText().toString()).toString();
                    JSONObject result = new JSONObject(raw);
                    org.json.JSONArray rows = result.getJSONArray("strings");
                    StringBuilder display = new StringBuilder();
                    display.append("File: ").append(result.getString("file_name"))
                           .append("\nUkuran: ").append(result.getLong("file_size"))
                           .append(" byte\nDitemukan: ").append(result.getInt("count"))
                           .append(" / ").append(result.getInt("limit")).append("\n\n");
                    for (int i = 0; i < rows.length(); i++) {
                        JSONObject row = rows.getJSONObject(i);
                        display.append("0x").append(Long.toHexString(row.getLong("offset")).toUpperCase())
                               .append("  ").append(row.getString("text")).append("\n");
                    }
                    if (rows.length() == 0) display.append("Tidak ada string ASCII yang memenuhi panjang minimum.");
                    if (result.getBoolean("truncated")) display.append("\n\n[Hasil dibatasi 300 string pertama]");
                    runOnUiThread(() -> { stringsResult.setText(display.toString()); extractStringsButton.setEnabled(true); });
                } catch (Exception e) {
                    runOnUiThread(() -> { stringsResult.setText("Gagal: " + e.getMessage()); extractStringsButton.setEnabled(true); });
                }
            });
        });

        LinearLayout future = card();
        LinearLayout.LayoutParams futureLp = params(-1, -2); futureLp.topMargin = dp(18);
        root.addView(future, futureLp);
        future.addView(text("ASSET WORKSPACE", 14, white, true));
        TextView note = text("Periksa ketersediaan UnityPy dan dependensi native di runtime Android. Pemeriksaan ini tidak memasang paket dan tidak mengubah file.", 12, muted, false);
        LinearLayout.LayoutParams noteLp = params(-1, -2); noteLp.topMargin = dp(8);
        future.addView(note, noteLp);
        probeUnityButton = button("CEK KOMPATIBILITAS UNITYPY", true);
        LinearLayout.LayoutParams probeLp = params(-1, dp(46)); probeLp.topMargin = dp(12);
        future.addView(probeUnityButton, probeLp);
        probeUnityButton.setOnClickListener(v -> runUnityProbe());
        Button browseBundleButton = button("BUKA BUNDLE (BACA-SAJА)", false);
        LinearLayout.LayoutParams browseBundleLp = params(-1, dp(46)); browseBundleLp.topMargin = dp(10);
        future.addView(browseBundleButton, browseBundleLp);
        TextView bundleBrowserView = text("Pilih file bundle, lalu buka inventaris asset jika UnityPy tersedia.", 10, muted, false);
        bundleBrowserView.setTypeface(Typeface.MONOSPACE); bundleBrowserView.setTextIsSelectable(true);
        LinearLayout.LayoutParams bundleViewLp = params(-1, -2); bundleViewLp.topMargin = dp(12);
        future.addView(bundleBrowserView, bundleViewLp);
        browseBundleButton.setOnClickListener(v -> {
            if (selectedFile == null) { status.setText("Pilih file bundle terlebih dahulu."); return; }
            browseBundleButton.setEnabled(false);
            bundleBrowserView.setText("Memuat bundle dan membaca metadata asset...");
            worker.execute(() -> {
                try {
                    PyObject module = Python.getInstance().getModule("android_bridge");
                    String raw = module.callAttr("open_bundle_readonly", selectedFile.getAbsolutePath(), "1000").toString();
                    JSONObject result = new JSONObject(raw);
                    org.json.JSONArray rows = result.getJSONArray("assets");
                    JSONObject types = result.getJSONObject("types");
                    StringBuilder display = new StringBuilder();
                    display.append("BUNDLE: ").append(result.getString("file_name"))
                           .append("\nUkuran: ").append(result.getLong("file_size"))
                           .append(" byte\nTotal asset: ").append(result.getInt("total_assets"))
                           .append("\nDitampilkan: ").append(result.getInt("shown_assets"))
                           .append("\n\nTIPE ASSET\n");
                    java.util.Iterator<String> keys = types.keys();
                    while (keys.hasNext()) { String key = keys.next(); display.append(key).append(": ").append(types.getInt(key)).append("\n"); }
                    display.append("\nDAFTAR ASSET\n");
                    for (int i = 0; i < rows.length(); i++) {
                        JSONObject item = rows.getJSONObject(i);
                        display.append("#").append(item.getInt("index"))
                               .append(" | ").append(item.getString("type"))
                               .append(" | Path ID: ").append(item.get("path_id"))
                               .append(" | Class: ").append(item.get("class_id"))
                               .append(" | ").append(item.getLong("size")).append(" B\n")
                               .append("  ").append(item.getString("name")).append("\n");
                    }
                    if (result.getBoolean("truncated")) display.append("\n[Daftar dibatasi 1000 asset pertama.]");
                    display.append("\n\nMODE BACA-SAJА — file asli tidak diubah.");
                    runOnUiThread(() -> { bundleBrowserView.setText(display.toString()); browseBundleButton.setEnabled(true); });
                } catch (Exception e) {
                    runOnUiThread(() -> { bundleBrowserView.setText("Bundle Browser belum dapat dijalankan: " + e.getMessage()); browseBundleButton.setEnabled(true); });
                }
            });
        });
        unityProbeView = text("Belum diperiksa.", 11, muted, false);
        unityProbeView.setTypeface(Typeface.MONOSPACE);
        unityProbeView.setTextIsSelectable(true);
        LinearLayout.LayoutParams probeTextLp = params(-1, -2); probeTextLp.topMargin = dp(12);
        future.addView(unityProbeView, probeTextLp);

        setContentView(scroll);
    }

    private void runAnalysis() {
        if (selectedFile == null) return;
        analyzeButton.setEnabled(false);
        status.setText("Sedang menganalisis file secara lokal...");
        worker.execute(() -> {
            try {
                PyObject module = Python.getInstance().getModule("android_bridge");
                String raw = module.callAttr("analyze_file", selectedFile.getAbsolutePath(), getFilesDir().getAbsolutePath()).toString();
                JSONObject result = new JSONObject(raw);
                String summary = result.getString("summary");
                txtReport = new File(result.getString("text_path"));
                jsonReport = new File(result.getString("json_path"));
                runOnUiThread(() -> {
                    reportView.setText(summary);
                    status.setText("Selesai: " + selectedFile.getName() + " (" + selectedFile.length() + " bytes)");
                    analyzeButton.setEnabled(true);
                    saveTxtButton.setEnabled(true);
                    saveJsonButton.setEnabled(true);
                });
            } catch (Exception e) {
                runOnUiThread(() -> {
                    status.setText("Analisis gagal: " + e.getMessage());
                    analyzeButton.setEnabled(true);
                });
            }
        });
    }

    private void runUnityProbe() {
        probeUnityButton.setEnabled(false);
        unityProbeView.setText("Memeriksa modul Python di runtime Android...");
        worker.execute(() -> {
            try {
                PyObject module = Python.getInstance().getModule("android_bridge");
                String raw = module.callAttr("probe_unitypy").toString();
                JSONObject result = new JSONObject(raw);
                org.json.JSONArray checks = result.getJSONArray("checks");
                StringBuilder report = new StringBuilder();
                report.append(result.getBoolean("ready") ? "UNITYPY DEPENDENCIES: READY\n" : "UNITYPY DEPENDENCIES: NOT READY\n");
                for (int i = 0; i < checks.length(); i++) {
                    JSONObject item = checks.getJSONObject(i);
                    report.append(item.getString("distribution"))
                          .append(" — ").append(item.getString("status"));
                    if (!item.isNull("version")) report.append(" (v").append(item.getString("version")).append(")");
                    if (!item.isNull("error")) report.append("\n  ").append(item.getString("error"));
                    report.append("\n");
                }
                runOnUiThread(() -> {
                    unityProbeView.setText(report.toString());
                    probeUnityButton.setEnabled(true);
                });
            } catch (Exception e) {
                runOnUiThread(() -> {
                    unityProbeView.setText("Pemeriksaan gagal: " + e.getMessage());
                    probeUnityButton.setEnabled(true);
                });
            }
        });
    }

    private void applyTextEdit() {
        if (selectedFile == null) return;
        String oldText = oldTextInput.getText().toString();
        String newText = newTextInput.getText().toString();
        applyEditButton.setEnabled(false);
        status.setText("Membuat salinan hasil edit...");
        worker.execute(() -> {
            try {
                PyObject module = Python.getInstance().getModule("android_bridge");
                String raw = module.callAttr("replace_utf8_text", selectedFile.getAbsolutePath(),
                        new File(getFilesDir(), "edited").getAbsolutePath(), oldText, newText).toString();
                JSONObject result = new JSONObject(raw);
                editedFile = new File(result.getString("output_path"));
                int count = result.getInt("replacement_count");
                runOnUiThread(() -> {
                    status.setText("Edit berhasil: " + count + " penggantian. File asli tetap aman.");
                    saveEditedButton.setEnabled(true);
                    applyEditButton.setEnabled(true);
                });
            } catch (Exception e) {
                runOnUiThread(() -> {
                    status.setText("Edit gagal: " + e.getMessage());
                    applyEditButton.setEnabled(true);
                });
            }
        });
    }

    private void createSaveIntent(int request) {
        File source;
        if (request == SAVE_TXT) source = txtReport;
        else if (request == SAVE_JSON) source = jsonReport;
        else source = editedFile;
        if (source == null || !source.exists()) return;
        Intent i = new Intent(Intent.ACTION_CREATE_DOCUMENT);
        i.addCategory(Intent.CATEGORY_OPENABLE);
        i.setType(request == SAVE_TXT ? "text/plain" : request == SAVE_JSON ? "application/json" : "application/octet-stream");
        i.putExtra(Intent.EXTRA_TITLE, source.getName());
        startActivityForResult(i, request);
    }

    @Override protected void onActivityResult(int request, int result, Intent data) {
        super.onActivityResult(request, result, data);
        if (result != RESULT_OK || data == null || data.getData() == null) return;
        Uri uri = data.getData();
        if (request == PICK_FILE) {
            worker.execute(() -> {
                try (InputStream in = getContentResolver().openInputStream(uri)) {
                    File dir = new File(getFilesDir(), "imports");
                    if (!dir.exists()) dir.mkdirs();
                    String name = "selected_asset.bin";
                    try (android.database.Cursor c = getContentResolver().query(uri, null, null, null, null)) {
                        if (c != null && c.moveToFirst()) {
                            int idx = c.getColumnIndex(android.provider.OpenableColumns.DISPLAY_NAME);
                            if (idx >= 0) { String n = c.getString(idx); if (n != null && !n.trim().isEmpty()) name = n.replaceAll("[^A-Za-z0-9._-]", "_"); }
                        }
                    }
                    File dest = new File(dir, name);
                    try (FileOutputStream out = new FileOutputStream(dest)) {
                        byte[] buffer = new byte[64 * 1024]; int n;
                        while ((n = in.read(buffer)) > 0) out.write(buffer, 0, n);
                    }
                    selectedFile = dest;
                    editedFile = null;
                    runOnUiThread(() -> {
                        status.setText("File dipilih: " + dest.getName());
                        analyzeButton.setEnabled(true);
                        applyEditButton.setEnabled(true);
                        saveEditedButton.setEnabled(false);
                    });
                } catch (Exception e) {
                    runOnUiThread(() -> status.setText("Gagal membuka file: " + e.getMessage()));
                }
            });
        } else if (request == SAVE_TXT || request == SAVE_JSON || request == SAVE_EDITED) {
            File source = request == SAVE_TXT ? txtReport : request == SAVE_JSON ? jsonReport : editedFile;
            worker.execute(() -> {
                try (InputStream in = new java.io.FileInputStream(source); OutputStream out = getContentResolver().openOutputStream(uri)) {
                    byte[] buffer = new byte[64 * 1024]; int n;
                    while ((n = in.read(buffer)) > 0) out.write(buffer, 0, n);
                    runOnUiThread(() -> Toast.makeText(this, request == SAVE_EDITED ? "File hasil edit berhasil diekspor." : "Laporan berhasil disimpan.", Toast.LENGTH_SHORT).show());
                } catch (Exception e) {
                    runOnUiThread(() -> Toast.makeText(this, "Gagal menyimpan: " + e.getMessage(), Toast.LENGTH_LONG).show());
                }
            });
        }
    }

    private LinearLayout card() {
        LinearLayout box = new LinearLayout(this); box.setOrientation(LinearLayout.VERTICAL);
        box.setPadding(dp(16), dp(16), dp(16), dp(16)); box.setBackgroundColor(panel); return box;
    }
    private Button button(String label, boolean primary) {
        Button b = new Button(this); b.setText(label); b.setAllCaps(false); b.setTextSize(12);
        b.setTypeface(null, Typeface.BOLD); b.setTextColor(white);
        b.setBackgroundTintList(android.content.res.ColorStateList.valueOf(primary ? red : Color.rgb(39, 45, 59)));
        return b;
    }
    private TextView text(String value, int size, int color, boolean bold) {
        TextView t = new TextView(this); t.setText(value); t.setTextSize(size); t.setTextColor(color);
        if (bold) t.setTypeface(Typeface.DEFAULT, Typeface.BOLD);
        return t;
    }
    private LinearLayout.LayoutParams params(int w, int h) { return new LinearLayout.LayoutParams(w, h); }
    private int dp(int value) { return Math.round(value * getResources().getDisplayMetrics().density); }
    @Override protected void onDestroy() { super.onDestroy(); worker.shutdown(); }
}
