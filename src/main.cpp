#define GImGui (ImGui::GetCurrentContext())

#include <imgui.h>
#include <config.h>
#include <core.h>
#include <gui/style.h>
#include <gui/gui.h>
#include <signal_path/signal_path.h>
#include <module.h>
#include <fstream>

#include <dsp/demod/psk.h>
#include <dsp/buffer/packer.h>
#include <dsp/routing/splitter.h>
#include <dsp/stream.h>
#include <dsp/convert/mono_to_stereo.h>

#include <gui/widgets/constellation_diagram.h>
#include <gui/widgets/file_select.h>
#include <gui/widgets/volume_meter.h>

// NEW: to read/set VFO offsets against the waterfall center frequency
#include <gui/widgets/waterfall.h>

#include <utils/flog.h>
#include <utils/net.h>

#include "dsp/bit_unpacker.h"
#include "dsp/dqpsk_sym_extr.h"
#include "dsp/pi4dqpsk.h"
#include "dsp/osmotetra_dec.h"
#include "gui_widgets.h"

#define CONCAT(a, b)    ((std::string(a) + b).c_str())

#define VFO_SAMPLERATE 36000
#define VFO_BANDWIDTH 30000
#define CLOCK_RECOVERY_BW 0.00628f
#define CLOCK_RECOVERY_DAMPN_F 0.707f
#define CLOCK_RECOVERY_REL_LIM 0.02f
#define RRC_TAP_COUNT 65
#define RRC_ALPHA 0.35f
#define AGC_RATE 0.02f
#define COSTAS_LOOP_BANDWIDTH 0.01f
#define FLL_LOOP_BANDWIDTH 0.006f

SDRPP_MOD_INFO {
    /* Name:            */ "tetra_demodulator",
    /* Description:     */ "Tetra demodulator for SDR++(output can be fed to tetra-rx from osmo-tetra)",
    /* Author:          */ "cropinghigh",
    /* Version:         */ 0, 2, 0,
    /* Max instances    */ -1
};

ConfigManager config;

class TetraDemodulatorModule : public ModuleManager::Instance {
public:
    TetraDemodulatorModule(std::string name) {
        this->name = name;

        // Load config
        config.acquire();
        if (!config.conf.contains(name) || !config.conf[name].contains("mode")) {
            config.conf[name]["mode"] = decoder_mode;
            config.conf[name]["hostname"] = "localhost";
            config.conf[name]["port"] = 8355;
            config.conf[name]["sending"] = false;

            // NEW: per-instance VFO lock
            config.conf[name]["lock_freq"] = false;
            config.conf[name]["lock_freq_hz"] = 0.0; // 0 = unset
        }
        decoder_mode = config.conf[name]["mode"];
        strcpy(hostname, std::string(config.conf[name]["hostname"]).c_str());
        port = config.conf[name]["port"];
        bool startNow = config.conf[name]["sending"];

        // NEW:
        lock_freq = config.conf[name].value("lock_freq", false);
        lock_freq_hz = config.conf[name].value("lock_freq_hz", 0.0);

        config.release(true);

        vfo = sigpath::vfoManager.createVFO(
            name,
            ImGui::WaterfallVFO::REF_CENTER,
            0,
            VFO_BANDWIDTH,
            VFO_SAMPLERATE,
            VFO_BANDWIDTH,
            VFO_BANDWIDTH,
            true
        );

        //Clock recov coeffs
        float recov_bandwidth = CLOCK_RECOVERY_BW;
        float recov_dampningFactor = CLOCK_RECOVERY_DAMPN_F;
        float recov_denominator = (1.0f + 2.0f * recov_dampningFactor * recov_bandwidth + recov_bandwidth * recov_bandwidth);
        float recov_mu = (4.0f * recov_dampningFactor * recov_bandwidth) / recov_denominator;
        float recov_omega = (4.0f * recov_bandwidth * recov_bandwidth) / recov_denominator;

        mainDemodulator.init(
            vfo->output,
            18000,
            VFO_SAMPLERATE,
            RRC_TAP_COUNT,
            RRC_ALPHA,
            AGC_RATE,
            COSTAS_LOOP_BANDWIDTH,
            FLL_LOOP_BANDWIDTH,
            recov_omega,
            recov_mu,
            CLOCK_RECOVERY_REL_LIM
        );

        constDiagSplitter.init(&mainDemodulator.out);
        constDiagSplitter.bindStream(&constDiagStream);
        constDiagSplitter.bindStream(&demodStream);

        constDiagReshaper.init(&constDiagStream, 1024, 0);
        constDiagSink.init(&constDiagReshaper.out, _constDiagSinkHandler, this);

        symbolExtractor.init(&demodStream);
        bitsUnpacker.init(&symbolExtractor.out);

        demodSink.init(&bitsUnpacker.out, _demodSinkHandler, this);

        osmotetradecoder.init(&bitsUnpacker.out);
        resamp.init(&osmotetradecoder.out, 8000.0, audioSampleRate);
        outconv.init(&resamp.out);

        // Initialize the sink
        srChangeHandler.ctx = this;
        srChangeHandler.handler = sampleRateChangeHandler;
        stream.init(&outconv.out, &srChangeHandler, audioSampleRate);
        sigpath::sinkManager.registerStream(name, &stream);

        mainDemodulator.start();
        constDiagSplitter.start();
        constDiagReshaper.start();
        constDiagSink.start();
        symbolExtractor.start();
        bitsUnpacker.start();
        setMode();
        resamp.start();
        outconv.start();
        stream.start();
        gui::menu.registerEntry(name, menuHandler, this, this);

        // NEW: apply lock after everything is registered
        applyLockedFrequency();

        if (startNow) {
            startNetwork();
        }
    }

    ~TetraDemodulatorModule() {
        if (isEnabled()) {
            disable();
        }
        gui::menu.removeEntry(name);
        sigpath::sinkManager.unregisterStream(name);
    }

    void postInit() {}

    void enable() {
        vfo = sigpath::vfoManager.createVFO(name, ImGui::WaterfallVFO::REF_CENTER, 0, 29000, 36000, 29000, 29000, true);
        mainDemodulator.setInput(vfo->output);

        mainDemodulator.start();
        constDiagSplitter.start();
        constDiagReshaper.start();
        constDiagSink.start();
        symbolExtractor.start();
        bitsUnpacker.start();
        setMode();
        resamp.start();
        outconv.start();
        stream.start();

        enabled = true;

        // NEW:
        applyLockedFrequency();
    }

    void disable() {
        mainDemodulator.stop();
        constDiagSplitter.stop();
        constDiagReshaper.stop();
        constDiagSink.stop();
        symbolExtractor.stop();
        bitsUnpacker.stop();
        osmotetradecoder.stop();
        demodSink.stop();
        resamp.stop();
        outconv.stop();
        stream.stop();
        sigpath::vfoManager.deleteVFO(vfo);
        enabled = false;
    }

    bool isEnabled() {
        return enabled;
    }

private:
    // =========================
    // NEW: VFO lock helpers
    // =========================

    // Returns the current absolute frequency (Hz) of THIS instance's VFO marker
    // using: waterfall center frequency + this VFO's centerOffset
    bool getThisVFOAbsHz(double& outHz) {
        // gui::waterfall.vfos is public in waterfall.h
        auto it = gui::waterfall.vfos.find(name);
        if (it == gui::waterfall.vfos.end()) return false;

        ImGui::WaterfallVFO* wfVfo = it->second;
        if (!wfVfo) return false;

        const double centerHz = gui::waterfall.getCenterFrequency();
        outHz = centerHz + wfVfo->centerOffset; // centerOffset is the actual tuned line
        return true;
    }

    // Apply stored lock_freq_hz by adjusting this VFO's centerOffset
    void applyLockedFrequency() {
        if (!lock_freq) return;
        if (!(lock_freq_hz > 0.0)) return;

        auto it = gui::waterfall.vfos.find(name);
        if (it == gui::waterfall.vfos.end()) return;

        ImGui::WaterfallVFO* wfVfo = it->second;
        if (!wfVfo) return;

        const double centerHz = gui::waterfall.getCenterFrequency();
        const double neededOffset = lock_freq_hz - centerHz;

        // Keep this instance locked even if user moves center frequency
        wfVfo->setCenterOffset(neededOffset);
    }

    void startNetwork() {
        stopNetwork();
        try {
            conn = net::openudp(hostname, port);
        } catch (std::runtime_error& e) {
            flog::error("Network error: %s\n", e.what());
        }
    }

    void stopNetwork() {
        if (conn) { conn->close(); }
    }

    void setMode() {
        if (decoder_mode == 0) {
            //osmo-tetra
            demodSink.stop();
            osmotetradecoder.start();
        } else {
            //network syms
            osmotetradecoder.stop();
            demodSink.start();
        }
        config.acquire();
        config.conf[name]["mode"] = decoder_mode;
        config.release(true);
    }

    static void menuHandler(void* ctx) {
        TetraDemodulatorModule* _this = (TetraDemodulatorModule*)ctx;
        float menuWidth = ImGui::GetContentRegionAvail().x;

        if (!_this->enabled) {
            style::beginDisabled();
        }

        // =========================
        // NEW: per-instance frequency lock UI
        // =========================
        ImGui::SeparatorText("Frequency (per instance)");

        // Show current VFO frequency
        double curHz = 0.0;
        if (_this->getThisVFOAbsHz(curHz)) {
            ImGui::Text("Current VFO: %.6f MHz", curHz / 1e6);
        } else {
            ImGui::TextDisabled("Current VFO: (not available)");
        }

        bool lf = _this->lock_freq;
        if (ImGui::Checkbox(CONCAT("Lock##_", _this->name), &lf)) {
            _this->lock_freq = lf;
            _this->configWriteLock();
            _this->applyLockedFrequency();
        }

        // Input frequency in MHz
        double mhz = _this->lock_freq_hz > 0.0 ? (_this->lock_freq_hz / 1e6) : 0.0;
        ImGui::SetNextItemWidth(menuWidth);
        if (ImGui::InputDouble(CONCAT("Tune (MHz)##_", _this->name), &mhz, 0.0125, 0.1, "%.6f")) {
            if (mhz > 0.0) {
                _this->lock_freq_hz = mhz * 1e6;
                _this->configWriteLock();
                _this->applyLockedFrequency();
            }
        }
        ImGui::TextDisabled("Example: 392.312500 MHz");

        // Button: take the CURRENT marker frequency and lock it
        if (ImGui::Button(CONCAT("Lock to current VFO freq##_", _this->name), ImVec2(menuWidth, 0))) {
            double hz = 0.0;
            if (_this->getThisVFOAbsHz(hz)) {
                _this->lock_freq_hz = hz;
                _this->lock_freq = true;
                _this->configWriteLock();
                _this->applyLockedFrequency();
            }
        }

        // If locked, keep applying each frame (so it stays locked if center moves)
        if (_this->lock_freq) {
            _this->applyLockedFrequency();
        }

        ImGui::Separator();

        // =========================
        // Existing UI
        // =========================

        ImGui::Text("Signal constellation: ");
        ImGui::SetNextItemWidth(menuWidth);
        _this->constDiag.draw();

        float avg = 1.0f - _this->symbolExtractor.standarderr;
        ImGui::Text("Signal quality: ");
        ImGui::SameLine();
        ImGui::SigQualityMeter(avg, 0.5f, 1.0f);
        ImGui::BoxIndicator(ImGui::GetFontSize() * 2, _this->symbolExtractor.sync ? IM_COL32(5, 230, 5, 255) : IM_COL32(230, 5, 5, 255));
        ImGui::SameLine();
        ImGui::Text(" Sync");

        ImGui::BeginGroup();
        ImGui::Columns(2, CONCAT("TetraModeColumns##_", _this->name), false);
        if (ImGui::RadioButton(CONCAT("OSMO-TETRA##_", _this->name), _this->decoder_mode == 0) && _this->decoder_mode != 0) {
            _this->decoder_mode = 0; //osmo-tetra
            _this->setMode();
        }
        ImGui::NextColumn();
        if (ImGui::RadioButton(CONCAT("NETSYMS##_", _this->name), _this->decoder_mode == 1) && _this->decoder_mode != 1) {
            _this->decoder_mode = 1; //network symbol streaming
            _this->setMode();
        }
        ImGui::Columns(1, CONCAT("EndTetraModeColumns##_", _this->name), false);
        ImGui::EndGroup();

        // (rest of your menuHandler stays unchanged...)
        // ---- SNIP ----
        // Keep your existing OSMO/NETSYMS UI here exactly as you had it.

        if (!_this->enabled) {
            style::endDisabled();
        }
    }

    // NEW helper: write lock settings
    void configWriteLock() {
        config.acquire();
        config.conf[name]["lock_freq"] = lock_freq;
        config.conf[name]["lock_freq_hz"] = lock_freq_hz;
        config.release(true);
    }

    static void _constDiagSinkHandler(dsp::complex_t* data, int count, void* ctx) {
        TetraDemodulatorModule* _this = (TetraDemodulatorModule*)ctx;
        dsp::complex_t* cdBuff = _this->constDiag.acquireBuffer();
        if (count == 1024) {
            memcpy(cdBuff, data, count * sizeof(dsp::complex_t));
        }
        _this->constDiag.releaseBuffer();
    }

    static void _demodSinkHandler(uint8_t* data, int count, void* ctx) {
        TetraDemodulatorModule* _this = (TetraDemodulatorModule*)ctx;
        if (_this->conn && _this->conn->isOpen()) {
            _this->conn->send(data, count);
        }
        for (int j = 0; j < count; j++) {
            for (int i = 0; i < 44; i++) {
                _this->tsfind_buffer[i] = _this->tsfind_buffer[i + 1];
            }
            _this->tsfind_buffer[44] = data[j];
            if (!memcmp(_this->tsfind_buffer, training_seq_n, sizeof(training_seq_n)) ||
                !memcmp(_this->tsfind_buffer, training_seq_p, sizeof(training_seq_p)) ||
                !memcmp(_this->tsfind_buffer, training_seq_q, sizeof(training_seq_q)) ||
                !memcmp(_this->tsfind_buffer, training_seq_N, sizeof(training_seq_N)) ||
                !memcmp(_this->tsfind_buffer, training_seq_P, sizeof(training_seq_P)) ||
                !memcmp(_this->tsfind_buffer, training_seq_x, sizeof(training_seq_x)) ||
                !memcmp(_this->tsfind_buffer, training_seq_X, sizeof(training_seq_X)) ||
                !memcmp(_this->tsfind_buffer, training_seq_y, sizeof(training_seq_y))
            ) {
                _this->tsfound = true;
                _this->symsbeforeexpire = 2048;
            }
            if (_this->symsbeforeexpire > 0) {
                _this->symsbeforeexpire--;
                if (_this->symsbeforeexpire == 0) {
                    _this->tsfound = false;
                }
            }
        }
    }

    static void sampleRateChangeHandler(float sampleRate, void* ctx) {
        TetraDemodulatorModule* _this = (TetraDemodulatorModule*)ctx;
        _this->audioSampleRate = sampleRate;
        _this->resamp.stop();
        _this->resamp.setOutSamplerate(_this->audioSampleRate);
        _this->resamp.start();
    }

    std::string name;
    bool enabled = true;

    VFOManager::VFO* vfo;

    dsp::demod::PI4DQPSK mainDemodulator;
    dsp::routing::Splitter<dsp::complex_t> constDiagSplitter;
    dsp::stream<dsp::complex_t> constDiagStream;
    dsp::buffer::Reshaper<dsp::complex_t> constDiagReshaper;
    dsp::sink::Handler<dsp::complex_t> constDiagSink;
    ImGui::ConstellationDiagram constDiag;

    dsp::stream<dsp::complex_t> demodStream;

    dsp::DQPSKSymbolExtractor symbolExtractor;
    dsp::BitUnpacker bitsUnpacker;

    dsp::sink::Handler<uint8_t> demodSink;

    dsp::osmotetradec osmotetradecoder;

    EventHandler<float> srChangeHandler;
    dsp::multirate::RationalResampler<float> resamp;
    dsp::convert::MonoToStereo outconv;
    SinkManager::Stream stream;
    double audioSampleRate = 48000.0;

    int decoder_mode = 0;

    // NEW: lock state
    bool lock_freq = false;
    double lock_freq_hz = 0.0;

    //Sequences from osmo-tetra-sq5bpf source
    static const constexpr uint8_t training_seq_n[22] = { 1,1, 0,1, 0,0, 0,0, 1,1, 1,0, 1,0, 0,1, 1,1, 0,1, 0,0 };
    static const constexpr uint8_t training_seq_p[22] = { 0,1, 1,1, 1,0, 1,0, 0,1, 0,0, 0,0, 1,1, 0,1, 1,1, 1,0 };
    static const constexpr uint8_t training_seq_q[22] = { 1,0, 1,1, 0,1, 1,1, 0,0, 0,0, 0,1, 1,0, 1,0, 1,1, 0,1 };
    static const constexpr uint8_t training_seq_N[33] = { 1,1,1, 0,0,1, 1,0,1, 1,1,1, 0,0,0, 1,1,1, 1,0,0, 0,1,1, 1,1,0, 0,0,0, 0,0,0 };
    static const constexpr uint8_t training_seq_P[33] = { 1,0,1, 0,1,1, 1,1,1, 1,0,1, 0,1,0, 1,0,1, 1,1,0, 0,0,1, 1,0,0, 0,1,0, 0,1,0 };
    static const constexpr uint8_t training_seq_x[30] = { 1,0, 0,1, 1,1, 0,1, 0,0, 0,0, 1,1, 1,0, 1,0, 0,1, 1,1, 0,1, 0,0, 0,0, 1,1 };
    static const constexpr uint8_t training_seq_X[45] = { 0,1,1,1,0,0,1,1,0,1,0,0,0,0,1,0,0,0,1,1,1,0,1,1,0,1,0,1,0,1,1,1,1,1,0,1,0,0,0,0,0,1,1,1,0 };
    static const constexpr uint8_t training_seq_y[38] = { 1,1, 0,0, 0,0, 0,1, 1,0, 0,1, 1,1, 0,0, 1,1, 1,0, 1,0, 0,1, 1,1, 0,0, 0,0, 0,1, 1,0, 0,1, 1,1 };

    uint8_t tsfind_buffer[45];
    bool tsfound = false;
    int symsbeforeexpire = 0;

    char hostname[1024];
    int port = 8355;

    std::shared_ptr<net::Socket> conn;
};

MOD_EXPORT void _INIT_() {
    std::string root = (std::string)core::args["root"];
    json def = json({});
    config.setPath(root + "/tetra_demodulator_config.json");
    config.load(def);
    config.enableAutoSave();
}

MOD_EXPORT ModuleManager::Instance* _CREATE_INSTANCE_(std::string name) {
    return new TetraDemodulatorModule(name);
}

MOD_EXPORT void _DELETE_INSTANCE_(void* instance) {
    delete (TetraDemodulatorModule*)instance;
}

MOD_EXPORT void _END_() {
    config.disableAutoSave();
    config.save();
}
