/**
 * ScamShield AI — Futuristic Experience Engine (main.js)
 * Implements:
 * A. Animated Digital Network & Floating Glowing Bubble Background Canvas
 * B. Interactive Futuristic AI Shield State Controller
 * C. Live Cyber Radar Connected to Actual Analysis Activity
 * D. Web Audio API Synthesizer Sound Engine (8 Sounds + Mute/Volume/Preview/Ambient + SpeechSynthesis)
 * E. Floating AI Assistant Orb (Text Chat, Voice Input, Spoken Replies, Feature Navigation)
 * F. Voice Wave Visualizer (Web Audio AnalyserNode + Live Microphone Waveform + Transcription + Scam Analysis)
 * G/H/I. Smart Notifications & Custom Appearance Settings (Dark/Light, Animations, Reduced Motion, Sound, Volume, BG)
 */

class ScamShieldSoundEngine {
    constructor() {
        this.ctx = null;
        this.ambientOsc = null;
        this.ambientGain = null;
        this.enabled = localStorage.getItem('ss_sound_enabled') !== 'off';
        this.ambientEnabled = localStorage.getItem('ss_ambient_enabled') === 'on';
        this.voiceEnabled = localStorage.getItem('ss_voice_enabled') !== 'off';
        this.volume = parseFloat(localStorage.getItem('ss_sound_volume') || '0.45');
    }

    _ensureContext() {
        if (!this.ctx) {
            const AudioCtx = window.AudioContext || window.webkitAudioContext;
            if (AudioCtx) {
                this.ctx = new AudioCtx();
            }
        }
        if (this.ctx && this.ctx.state === 'suspended') {
            this.ctx.resume();
        }
        return this.ctx;
    }

    setVolume(val) {
        this.volume = Math.max(0, Math.min(1, parseFloat(val)));
        localStorage.setItem('ss_sound_volume', String(this.volume));
        if (this.ambientGain && this.ctx) {
            this.ambientGain.gain.setValueAtTime(this.volume * 0.08, this.ctx.currentTime);
        }
    }

    setEnabled(flag) {
        this.enabled = Boolean(flag);
        localStorage.setItem('ss_sound_enabled', this.enabled ? 'on' : 'off');
        if (!this.enabled) {
            this.stopAmbient();
            if ('speechSynthesis' in window) window.speechSynthesis.cancel();
        }
    }

    play(type) {
        if (!this.enabled || this.volume <= 0.01) return;
        const ctx = this._ensureContext();
        if (!ctx) return;

        const now = ctx.currentTime;
        const master = ctx.createGain();
        master.gain.setValueAtTime(Math.min(0.65, this.volume), now);
        master.connect(ctx.destination);

        const playTone = (freq, endFreq, startOffset, duration, wave = 'sine', gainScale = 0.5) => {
            const osc = ctx.createOscillator();
            const g = ctx.createGain();
            osc.type = wave;
            osc.frequency.setValueAtTime(freq, now + startOffset);
            if (endFreq && endFreq !== freq) {
                osc.frequency.exponentialRampToValueAtTime(endFreq, now + startOffset + duration);
            }
            g.gain.setValueAtTime(0.001, now + startOffset);
            g.gain.linearRampToValueAtTime(gainScale, now + startOffset + 0.02);
            g.gain.exponentialRampToValueAtTime(0.001, now + startOffset + duration);
            osc.connect(g);
            g.connect(master);
            osc.start(now + startOffset);
            osc.stop(now + startOffset + duration + 0.02);
        };

        switch (type) {
            case 'startup':
                playTone(330, 330, 0.00, 0.14, 'sine', 0.35);
                playTone(440, 440, 0.10, 0.14, 'sine', 0.35);
                playTone(659.25, 880, 0.20, 0.28, 'triangle', 0.40);
                break;
            case 'scanner':
                playTone(280, 760, 0.00, 0.26, 'sine', 0.40);
                playTone(760, 520, 0.22, 0.18, 'triangle', 0.30);
                break;
            case 'complete':
                playTone(523.25, 523.25, 0.00, 0.14, 'sine', 0.40);
                playTone(783.99, 783.99, 0.12, 0.25, 'sine', 0.45);
                break;
            case 'low_risk':
                playTone(440, 440, 0.00, 0.22, 'sine', 0.32);
                playTone(554.37, 554.37, 0.05, 0.22, 'sine', 0.32);
                playTone(659.25, 659.25, 0.10, 0.28, 'sine', 0.35);
                break;
            case 'high_risk':
                playTone(480, 390, 0.00, 0.18, 'sawtooth', 0.28);
                playTone(480, 390, 0.22, 0.22, 'sawtooth', 0.28);
                break;
            case 'critical_risk':
                playTone(620, 420, 0.00, 0.15, 'triangle', 0.36);
                playTone(620, 420, 0.18, 0.15, 'triangle', 0.36);
                playTone(680, 360, 0.36, 0.24, 'triangle', 0.38);
                break;
            default:
                playTone(520, 640, 0.00, 0.15, 'sine', 0.30);
        }
    }

    toggleAmbient(turnOn) {
        this.ambientEnabled = Boolean(turnOn);
        localStorage.setItem('ss_ambient_enabled', this.ambientEnabled ? 'on' : 'off');
        if (!this.ambientEnabled || !this.enabled) {
            this.stopAmbient();
            return;
        }
        const ctx = this._ensureContext();
        if (!ctx || this.ambientOsc) return;

        this.ambientOsc = ctx.createOscillator();
        this.ambientGain = ctx.createGain();
        this.ambientOsc.type = 'sine';
        this.ambientOsc.frequency.setValueAtTime(110, ctx.currentTime);
        this.ambientGain.gain.setValueAtTime(this.volume * 0.06, ctx.currentTime);
        this.ambientOsc.connect(this.ambientGain);
        this.ambientGain.connect(ctx.destination);
        this.ambientOsc.start();
    }

    stopAmbient() {
        if (this.ambientOsc) {
            try { this.ambientOsc.stop(); } catch (e) {}
            try { this.ambientOsc.disconnect(); } catch (e) {}
            this.ambientOsc = null;
            this.ambientGain = null;
        }
    }

    speak(text) {
        if (!this.enabled || !this.voiceEnabled || !('speechSynthesis' in window)) return;
        window.speechSynthesis.cancel();
        const utter = new SpeechSynthesisUtterance(text);
        utter.volume = Math.min(0.85, Math.max(0.2, this.volume));
        utter.rate = 1.03;
        utter.pitch = 1.0;
        window.speechSynthesis.speak(utter);
    }
}

window.scamShieldAudio = new ScamShieldSoundEngine();

window.pushSmartToast = function(title, detail, severity = 'info') {
    const container = document.getElementById('smartToastStack');
    if (!container) return;

    const colors = {
        info: '#00d4ff',
        success: '#10b981',
        warning: '#f59e0b',
        danger: '#ef4444'
    };
    const item = document.createElement('div');
    item.className = 'smart-toast-item';
    item.style.borderLeftColor = colors[severity] || '#00d4ff';
    item.innerHTML = `
        <div class="d-flex justify-content-between align-items-center mb-1">
            <strong class="small text-white">${title}</strong>
            <button type="button" class="btn-close btn-close-white" style="font-size: 0.65rem;"></button>
        </div>
        <div class="text-secondary" style="font-size: 0.78rem;">${detail}</div>
    `;
    item.querySelector('button').addEventListener('click', () => item.remove());
    container.appendChild(item);
    setTimeout(() => {
        if (item.parentNode) item.remove();
    }, 5000);
};

document.addEventListener('DOMContentLoaded', () => {
    const htmlEl = document.documentElement;

    const savedTheme = localStorage.getItem('ss_theme') || 'dark';
    const savedAnim = localStorage.getItem('ss_animations') || 'on';
    const savedBg = localStorage.getItem('ss_bg_effects') || 'on';

    htmlEl.setAttribute('data-scamshield-theme', savedTheme);
    htmlEl.setAttribute('data-animations', savedAnim);
    htmlEl.setAttribute('data-bg-effects', savedBg);

    const applyPreferenceControls = () => {
        const themeSel = document.getElementById('prefThemeSelect');
        const animChk = document.getElementById('prefAnimSwitch');
        const bgChk = document.getElementById('prefBgSwitch');
        const soundChk = document.getElementById('prefSoundSwitch');
        const volRange = document.getElementById('prefVolumeRange');
        const ambChk = document.getElementById('prefAmbientSwitch');
        const voiceChk = document.getElementById('prefVoiceSwitch');

        if (themeSel) {
            themeSel.value = localStorage.getItem('ss_theme') || 'dark';
            themeSel.addEventListener('change', (e) => {
                localStorage.setItem('ss_theme', e.target.value);
                htmlEl.setAttribute('data-scamshield-theme', e.target.value);
                window.pushSmartToast('Appearance Updated', `Switched to ${e.target.value.toUpperCase()} mode.`, 'info');
            });
        }
        if (animChk) {
            animChk.checked = (localStorage.getItem('ss_animations') || 'on') === 'on';
            animChk.addEventListener('change', (e) => {
                const v = e.target.checked ? 'on' : 'off';
                localStorage.setItem('ss_animations', v);
                htmlEl.setAttribute('data-animations', v);
            });
        }
        if (bgChk) {
            bgChk.checked = (localStorage.getItem('ss_bg_effects') || 'on') === 'on';
            bgChk.addEventListener('change', (e) => {
                const v = e.target.checked ? 'on' : 'off';
                localStorage.setItem('ss_bg_effects', v);
                htmlEl.setAttribute('data-bg-effects', v);
            });
        }
        if (soundChk) {
            soundChk.checked = window.scamShieldAudio.enabled;
            soundChk.addEventListener('change', (e) => {
                window.scamShieldAudio.setEnabled(e.target.checked);
                updateTopbarMuteIcon();
            });
        }
        if (volRange) {
            volRange.value = String(Math.round(window.scamShieldAudio.volume * 100));
            volRange.addEventListener('input', (e) => {
                window.scamShieldAudio.setVolume(parseInt(e.target.value, 10) / 100);
            });
        }
        if (ambChk) {
            ambChk.checked = window.scamShieldAudio.ambientEnabled;
            ambChk.addEventListener('change', (e) => {
                window.scamShieldAudio.toggleAmbient(e.target.checked);
            });
        }
        if (voiceChk) {
            voiceChk.checked = window.scamShieldAudio.voiceEnabled;
            voiceChk.addEventListener('change', (e) => {
                window.scamShieldAudio.voiceEnabled = e.target.checked;
                localStorage.setItem('ss_voice_enabled', e.target.checked ? 'on' : 'off');
            });
        }
    };
    applyPreferenceControls();

    const topMuteBtn = document.getElementById('topSoundToggleBtn');
    const topThemeBtn = document.getElementById('topThemeToggleBtn');

    function updateTopbarMuteIcon() {
        if (!topMuteBtn) return;
        topMuteBtn.innerHTML = window.scamShieldAudio.enabled
            ? '<i class="fa-solid fa-volume-high text-cyan"></i>'
            : '<i class="fa-solid fa-volume-xmark text-secondary"></i>';
    }
    updateTopbarMuteIcon();

    if (topMuteBtn) {
        topMuteBtn.addEventListener('click', () => {
            window.scamShieldAudio.setEnabled(!window.scamShieldAudio.enabled);
            updateTopbarMuteIcon();
            if (window.scamShieldAudio.enabled) {
                window.scamShieldAudio.play('startup');
                window.pushSmartToast('Audio Synthesizer Active', 'Futuristic sound effects enabled.', 'info');
            } else {
                window.pushSmartToast('Audio Muted', 'All sound effects and voice alerts muted.', 'info');
            }
        });
    }

    if (topThemeBtn) {
        topThemeBtn.addEventListener('click', () => {
            const cur = htmlEl.getAttribute('data-scamshield-theme') === 'light' ? 'dark' : 'light';
            localStorage.setItem('ss_theme', cur);
            htmlEl.setAttribute('data-scamshield-theme', cur);
            window.scamShieldAudio.play('complete');
        });
    }

    const canvas = document.getElementById('cyberBgCanvas');
    if (canvas && canvas.getContext) {
        const ctx = canvas.getContext('2d');
        let width = (canvas.width = window.innerWidth);
        let height = (canvas.height = window.innerHeight);

        window.addEventListener('resize', () => {
            width = canvas.width = window.innerWidth;
            height = canvas.height = window.innerHeight;
        });

        const particleCount = Math.min(42, Math.floor(width / 36));
        const particles = Array.from({ length: particleCount }, () => ({
            x: Math.random() * width,
            y: Math.random() * height,
            vx: (Math.random() - 0.5) * 0.45,
            vy: (Math.random() - 0.5) * 0.45,
            r: Math.random() * 2.2 + 1.2
        }));

        const bubbles = Array.from({ length: 10 }, () => ({
            x: Math.random() * width,
            y: Math.random() * height,
            vy: -(Math.random() * 0.35 + 0.12),
            r: Math.random() * 26 + 10,
            alpha: Math.random() * 0.12 + 0.04
        }));

        function drawNetwork() {
            if (htmlEl.getAttribute('data-bg-effects') !== 'off' && htmlEl.getAttribute('data-animations') !== 'off') {
                ctx.clearRect(0, 0, width, height);

                for (const b of bubbles) {
                    b.y += b.vy;
                    if (b.y + b.r < 0) {
                        b.y = height + b.r;
                        b.x = Math.random() * width;
                    }
                    const grad = ctx.createRadialGradient(b.x, b.y, 1, b.x, b.y, b.r);
                    grad.addColorStop(0, `rgba(0, 212, 255, ${b.alpha})`);
                    grad.addColorStop(1, 'rgba(0, 102, 255, 0)');
                    ctx.fillStyle = grad;
                    ctx.beginPath();
                    ctx.arc(b.x, b.y, b.r, 0, Math.PI * 2);
                    ctx.fill();
                }

                for (let i = 0; i < particles.length; i++) {
                    const p = particles[i];
                    p.x += p.vx;
                    p.y += p.vy;
                    if (p.x < 0 || p.x > width) p.vx *= -1;
                    if (p.y < 0 || p.y > height) p.vy *= -1;

                    ctx.fillStyle = 'rgba(0, 212, 255, 0.55)';
                    ctx.beginPath();
                    ctx.arc(p.x, p.y, p.r, 0, Math.PI * 2);
                    ctx.fill();

                    for (let j = i + 1; j < particles.length; j++) {
                        const p2 = particles[j];
                        const dx = p.x - p2.x;
                        const dy = p.y - p2.y;
                        const dist = Math.sqrt(dx * dx + dy * dy);
                        if (dist < 135) {
                            ctx.strokeStyle = `rgba(0, 212, 255, ${(1 - dist / 135) * 0.18})`;
                            ctx.lineWidth = 1;
                            ctx.beginPath();
                            ctx.moveTo(p.x, p.y);
                            ctx.lineTo(p2.x, p2.y);
                            ctx.stroke();
                        }
                    }
                }
            }
            requestAnimationFrame(drawNetwork);
        }
        requestAnimationFrame(drawNetwork);
    }

    const orbBtn = document.getElementById('aiAssistantOrb');
    const orbPanel = document.getElementById('aiAssistantPanel');
    const closeOrbBtn = document.getElementById('closeAiAssistantBtn');
    const aiChatForm = document.getElementById('aiAssistantForm');
    const aiChatInput = document.getElementById('aiAssistantInput');
    const aiChatLog = document.getElementById('aiAssistantChatLog');
    const aiMicBtn = document.getElementById('aiAssistantMicBtn');

    if (orbBtn && orbPanel) {
        orbBtn.addEventListener('click', () => {
            orbPanel.classList.toggle('open');
            if (orbPanel.classList.contains('open')) {
                window.scamShieldAudio.play('startup');
            }
        });
    }
    if (closeOrbBtn && orbPanel) {
        closeOrbBtn.addEventListener('click', () => orbPanel.classList.remove('open'));
    }

    function appendAssistantMsg(sender, htmlText) {
        if (!aiChatLog) return;
        const div = document.createElement('div');
        div.className = sender === 'user'
            ? 'p-2 px-3 rounded-3 bg-primary bg-opacity-25 text-white small ms-4 mb-2 text-end'
            : 'p-2 px-3 rounded-3 bg-dark border border-info border-opacity-25 text-secondary small me-3 mb-2';
        div.innerHTML = htmlText;
        aiChatLog.appendChild(div);
        aiChatLog.scrollTop = aiChatLog.scrollHeight;
    }

    function generateAssistantReply(query) {
        const q = query.toLowerCase();
        if (q.includes('upi') || q.includes('pin') || q.includes('payment') || q.includes('olx')) {
            return {
                speech: 'Entering a UPI PIN always deducts money from your bank account. It never receives money. Opening the Payment Request Analyzer for you.',
                html: '<strong>UPI Collect Rule:</strong> Entering a 4/6-digit UPI PIN <em>always deducts funds</em>. Never enter a PIN to receive money. <a href="/analyzer/?channel=payment" class="text-cyan fw-bold d-block mt-1">Open Payment Analyzer →</a>'
            };
        }
        if (q.includes('url') || q.includes('link') || q.includes('website') || q.includes('http')) {
            return {
                speech: 'ScamShield AI inspects URLs statically without visiting them. Look out for raw IP addresses, unencrypted HTTP, and dot X Y Z domains.',
                html: 'Our <strong>Static URL Inspector</strong> checks HTTPS, raw IPv4 hosts, Punycode (<code>xn--</code>), and brand spoofing safely without visiting the link. <a href="/analyzer/?channel=url" class="text-cyan fw-bold d-block mt-1">Open URL Analyzer →</a>'
            };
        }
        if (q.includes('whatsapp') || q.includes('task') || q.includes('arrest')) {
            return {
                speech: 'Police and CBI officers never conduct Digital Arrest interrogations over WhatsApp video calls or ask for money transfers.',
                html: 'Law enforcement never conducts <strong>"Digital Arrests"</strong> on WhatsApp or demands prepaid task deposits. <a href="/analyzer/?channel=whatsapp" class="text-cyan fw-bold d-block mt-1">Open WhatsApp Analyzer →</a>'
            };
        }
        if (q.includes('case') || q.includes('investigat') || q.includes('correlat')) {
            return {
                speech: 'The Investigation Center groups suspicious messages and automatically finds shared phone numbers, domains, and UPI handles.',
                html: 'Use the <strong>AI Investigation Center</strong> to correlate shared phone numbers, domains, and UPI IDs across multiple artifacts. <a href="/investigations/" class="text-cyan fw-bold d-block mt-1">Open Investigation Center →</a>'
            };
        }
        return {
            speech: 'I can help you analyze suspicious SMS, emails, URLs, WhatsApp messages, social media DMs, or payment requests. Tell me what you received.',
            html: 'I can explain risk scores, inspect suspicious indicators, or take you to any module: <div class="d-flex flex-wrap gap-1 mt-1"><a href="/analyzer/?channel=sms" class="badge bg-info text-dark text-decoration-none">SMS</a><a href="/analyzer/?channel=email" class="badge bg-info text-dark text-decoration-none">Email</a><a href="/analyzer/?channel=url" class="badge bg-info text-dark text-decoration-none">URL</a><a href="/investigations/" class="badge bg-info text-dark text-decoration-none">Cases</a></div>'
        };
    }

    if (aiChatForm) {
        aiChatForm.addEventListener('submit', (e) => {
            e.preventDefault();
            const val = (aiChatInput.value || '').trim();
            if (!val) return;
            appendAssistantMsg('user', val);
            aiChatInput.value = '';
            const reply = generateAssistantReply(val);
            setTimeout(() => {
                appendAssistantMsg('bot', reply.html);
                window.scamShieldAudio.play('complete');
                window.scamShieldAudio.speak(reply.speech);
            }, 220);
        });
    }

    if (aiMicBtn) {
        aiMicBtn.addEventListener('click', () => {
            const SpeechRec = window.SpeechRecognition || window.webkitSpeechRecognition;
            if (!SpeechRec) {
                window.pushSmartToast('Voice Input Unavailable', 'Your browser does not support Web Speech recognition. Use text chat instead.', 'warning');
                return;
            }
            const rec = new SpeechRec();
            rec.lang = 'en-US';
            aiMicBtn.classList.add('btn-danger');
            window.scamShieldAudio.play('scanner');
            rec.onresult = (ev) => {
                const transcript = ev.results[0][0].transcript;
                if (aiChatInput) aiChatInput.value = transcript;
                aiMicBtn.classList.remove('btn-danger');
                aiChatForm.dispatchEvent(new Event('submit'));
            };
            rec.onerror = () => aiMicBtn.classList.remove('btn-danger');
            rec.onend = () => aiMicBtn.classList.remove('btn-danger');
            rec.start();
        });
    }

    const startVoiceBtn = document.getElementById('startVoiceWaveBtn');
    const stopVoiceBtn = document.getElementById('stopVoiceWaveBtn');
    const voiceCanvas = document.getElementById('voiceWaveformCanvas');
    const voiceStatusEl = document.getElementById('voiceRecordStatus');
    const voiceTimerEl = document.getElementById('voiceRecordTimer');
    const voiceTranscriptInput = document.getElementById('voiceTranscriptText');

    let mediaStream = null;
    let audioAnalyser = null;
    let waveAnimId = null;
    let timerInterval = null;
    let recordSeconds = 0;
    let speechRecognizer = null;

    if (startVoiceBtn && stopVoiceBtn && voiceCanvas) {
        const vCtx = voiceCanvas.getContext('2d');

        const drawIdleWave = () => {
            vCtx.clearRect(0, 0, voiceCanvas.width, voiceCanvas.height);
            vCtx.strokeStyle = 'rgba(0, 212, 255, 0.35)';
            vCtx.lineWidth = 2;
            vCtx.beginPath();
            vCtx.moveTo(0, voiceCanvas.height / 2);
            vCtx.lineTo(voiceCanvas.width, voiceCanvas.height / 2);
            vCtx.stroke();
        };
        drawIdleWave();

        startVoiceBtn.addEventListener('click', async () => {
            try {
                mediaStream = await navigator.mediaDevices.getUserMedia({ audio: true });
                const audioCtx = window.scamShieldAudio._ensureContext();
                const source = audioCtx.createMediaStreamSource(mediaStream);
                audioAnalyser = audioCtx.createAnalyser();
                audioAnalyser.fftSize = 256;
                source.connect(audioAnalyser);

                startVoiceBtn.disabled = true;
                stopVoiceBtn.disabled = false;
                recordSeconds = 0;
                if (voiceStatusEl) voiceStatusEl.innerHTML = '<span class="text-danger fw-bold"><i class="fa-solid fa-circle-dot me-1"></i>Recording Live Audio...</span>';
                window.scamShieldAudio.play('scanner');

                timerInterval = setInterval(() => {
                    recordSeconds++;
                    const m = String(Math.floor(recordSeconds / 60)).padStart(2, '0');
                    const s = String(recordSeconds % 60).padStart(2, '0');
                    if (voiceTimerEl) voiceTimerEl.textContent = `${m}:${s}`;
                }, 1000);

                const SpeechRec = window.SpeechRecognition || window.webkitSpeechRecognition;
                if (SpeechRec) {
                    speechRecognizer = new SpeechRec();
                    speechRecognizer.continuous = true;
                    speechRecognizer.interimResults = true;
                    speechRecognizer.onresult = (e) => {
                        let txt = '';
                        for (let i = 0; i < e.results.length; i++) {
                            txt += e.results[i][0].transcript + ' ';
                        }
                        if (voiceTranscriptInput) voiceTranscriptInput.value = txt.trim();
                    };
                    try { speechRecognizer.start(); } catch (err) {}
                }

                const bufferLength = audioAnalyser.frequencyBinCount;
                const dataArray = new Uint8Array(bufferLength);

                const renderWaveform = () => {
                    if (!audioAnalyser) return;
                    audioAnalyser.getByteTimeDomainData(dataArray);
                    vCtx.fillStyle = 'rgba(6, 11, 25, 0.85)';
                    vCtx.fillRect(0, 0, voiceCanvas.width, voiceCanvas.height);
                    vCtx.lineWidth = 2.2;
                    vCtx.strokeStyle = '#00d4ff';
                    vCtx.beginPath();

                    const sliceWidth = voiceCanvas.width / bufferLength;
                    let x = 0;
                    for (let i = 0; i < bufferLength; i++) {
                        const v = dataArray[i] / 128.0;
                        const y = (v * voiceCanvas.height) / 2;
                        if (i === 0) vCtx.moveTo(x, y);
                        else vCtx.lineTo(x, y);
                        x += sliceWidth;
                    }
                    vCtx.lineTo(voiceCanvas.width, voiceCanvas.height / 2);
                    vCtx.stroke();
                    waveAnimId = requestAnimationFrame(renderWaveform);
                };
                renderWaveform();
            } catch (err) {
                window.pushSmartToast('Microphone Access Denied or Unavailable', 'You can still paste or type a voice call transcript below to analyze it.', 'warning');
                if (voiceTranscriptInput && !voiceTranscriptInput.value) {
                    voiceTranscriptInput.value = 'Hello, this is Cyber Crime Police Officer speaking. Your Aadhaar is linked to money laundering. Join WhatsApp video call for Digital Arrest and transfer funds to RBI safe account immediately.';
                }
            }
        });

        stopVoiceBtn.addEventListener('click', () => {
            if (waveAnimId) cancelAnimationFrame(waveAnimId);
            if (timerInterval) clearInterval(timerInterval);
            if (speechRecognizer) {
                try { speechRecognizer.stop(); } catch (e) {}
            }
            if (mediaStream) {
                mediaStream.getTracks().forEach(t => t.stop());
                mediaStream = null;
            }
            audioAnalyser = null;
            startVoiceBtn.disabled = false;
            stopVoiceBtn.disabled = true;
            if (voiceStatusEl) voiceStatusEl.innerHTML = '<span class="text-success fw-bold"><i class="fa-solid fa-check-circle me-1"></i>Audio Captured — Ready to Submit</span>';
            window.scamShieldAudio.play('complete');
        });
    }

    const sidebar = document.getElementById('appSidebar');
    const toggleBtn = document.getElementById('mobileMenuBtn');
    const closeBtn = document.getElementById('closeSidebarBtn');

    if (toggleBtn && sidebar) {
        toggleBtn.addEventListener('click', () => sidebar.classList.toggle('mobile-open'));
    }
    if (closeBtn && sidebar) {
        closeBtn.addEventListener('click', () => sidebar.classList.remove('mobile-open'));
    }

    const channelTabs = document.querySelectorAll('.channel-tab-btn');
    const channelForms = document.querySelectorAll('.channel-form-pane');

    channelTabs.forEach(btn => {
        btn.addEventListener('click', () => {
            const targetChannel = btn.getAttribute('data-channel');
            channelTabs.forEach(b => b.classList.remove('active'));
            btn.classList.add('active');
            window.scamShieldAudio.play('scanner');

            channelForms.forEach(pane => {
                if (pane.getAttribute('data-channel-pane') === targetChannel) {
                    pane.classList.remove('d-none');
                } else {
                    pane.classList.add('d-none');
                }
            });

            const url = new URL(window.location.href);
            url.searchParams.set('channel', targetChannel);
            window.history.replaceState({}, '', url.toString());
        });
    });

    const sampleButtons = document.querySelectorAll('.fill-sample-btn');
    sampleButtons.forEach(btn => {
        btn.addEventListener('click', () => {
            const targetForm = btn.closest('form');
            if (!targetForm) return;
            const contentInput = targetForm.querySelector('[name="content"]');
            const senderInput = targetForm.querySelector('[name="subject_or_sender"]');
            const extraInput = targetForm.querySelector('[name="platform_or_method"]');
            const amountInput = targetForm.querySelector('[name="amount_requested"]');

            if (contentInput) contentInput.value = btn.getAttribute('data-sample-content') || '';
            if (senderInput && btn.getAttribute('data-sample-sender')) senderInput.value = btn.getAttribute('data-sample-sender');
            if (extraInput && btn.getAttribute('data-sample-extra')) extraInput.value = btn.getAttribute('data-sample-extra');
            if (amountInput && btn.getAttribute('data-sample-amount')) amountInput.value = btn.getAttribute('data-sample-amount');
            window.scamShieldAudio.play('complete');
        });
    });

    const scanForms = document.querySelectorAll('.scam-scan-form');
    const loadingOverlay = document.getElementById('scanLoadingOverlay');

    scanForms.forEach(form => {
        form.addEventListener('submit', (e) => {
            const contentField = form.querySelector('[name="content"]');
            if (!contentField || !contentField.value.trim()) {
                e.preventDefault();
                window.scamShieldAudio.play('high_risk');
                window.pushSmartToast('Validation Error', 'Please enter text or a URL to analyze before submitting.', 'danger');
                return;
            }
            window.scamShieldAudio.play('scanner');
            const shieldEl = document.getElementById('dashboardAiShield');
            if (shieldEl) shieldEl.setAttribute('data-shield-state', 'scanning');
            if (loadingOverlay) loadingOverlay.classList.add('show');
        });
    });

    const confirmDeleteForms = document.querySelectorAll('.confirm-delete-form');
    confirmDeleteForms.forEach(form => {
        form.addEventListener('submit', (e) => {
            const msg = form.getAttribute('data-confirm-message') || 'Are you sure you want to permanently delete this record?';
            if (!window.confirm(msg)) {
                e.preventDefault();
            }
        });
    });

    const resultScoreHolder = document.querySelector('[data-result-risk-score]');
    if (resultScoreHolder) {
        const sc = parseInt(resultScoreHolder.getAttribute('data-result-risk-score') || '0', 10);
        if (sc >= 75) {
            window.scamShieldAudio.play('critical_risk');
            window.pushSmartToast('Critical Risk Detected', `Analysis scored ${sc}/100 (Critical Risk). Review safety actions immediately.`, 'danger');
        } else if (sc >= 50) {
            window.scamShieldAudio.play('high_risk');
            window.pushSmartToast('High Risk Detected', `Analysis scored ${sc}/100 (High Risk).`, 'warning');
        } else {
            window.scamShieldAudio.play('low_risk');
            window.pushSmartToast('Scan Completed', `Analysis scored ${sc}/100.`, 'success');
        }
    }
});
