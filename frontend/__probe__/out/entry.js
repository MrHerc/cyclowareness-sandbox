import { renderToString } from "react-dom/server";
import { Link, MemoryRouter, Route, Routes, useNavigate, useParams } from "react-router-dom";
import { useEffect, useId, useRef, useState } from "react";
import { Activity, ArrowLeft, ArrowRight, Braces, CheckCircle2, ChevronRight, Circle, CircleAlert, Cpu, Download, FileSearch, FileText, FileUp, Flag, Link2, Loader2, Lock, Plus, RefreshCw, Share2, ShieldAlert, ShieldCheck, Siren } from "lucide-react";
import { Fragment, jsx, jsxs } from "react/jsx-runtime";
import { Bar, BarChart, Cell, Pie, PieChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
//#region src/components/ui.tsx
function cx(...parts) {
	return parts.filter(Boolean).join(" ");
}
function Panel({ title, subtitle, actions, footer, tone = "default", padded = true, className, children, ...rest }) {
	return /* @__PURE__ */ jsxs("section", {
		className: cx("rounded-panel border", {
			default: "border-hair bg-panel",
			feature: "border-brand/30 bg-panel",
			quiet: "border-transparent bg-transparent"
		}[tone], className),
		...rest,
		children: [
			(title || actions) && /* @__PURE__ */ jsxs("header", {
				className: cx("flex items-start justify-between gap-4", padded ? "px-5 pt-4" : "px-0 pt-0", children ? "pb-3" : "pb-4"),
				children: [/* @__PURE__ */ jsxs("div", {
					className: "min-w-0",
					children: [title && /* @__PURE__ */ jsx("h2", {
						className: "text-h truncate",
						children: title
					}), subtitle && /* @__PURE__ */ jsx("p", {
						className: "text-sm mt-0.5 text-c2",
						children: subtitle
					})]
				}), actions && /* @__PURE__ */ jsx("div", {
					className: "flex shrink-0 items-center gap-2",
					children: actions
				})]
			}),
			/* @__PURE__ */ jsx("div", {
				className: cx(padded && (title || actions ? "px-5 pb-5" : "p-5")),
				children
			}),
			footer && /* @__PURE__ */ jsx("div", {
				className: cx("border-t border-hair", padded && "px-5 py-3"),
				children: footer
			})
		]
	});
}
/** Small all-caps rule above a sub-grouping inside a Panel. */
function GroupLabel({ children, right }) {
	return /* @__PURE__ */ jsxs("div", {
		className: "mb-2.5 flex items-baseline justify-between gap-3",
		children: [/* @__PURE__ */ jsx("h3", {
			className: "label text-c3",
			children
		}), right]
	});
}
function PageHeader({ title, lede, actions, breadcrumb }) {
	return /* @__PURE__ */ jsxs("header", {
		className: "flex flex-wrap items-end justify-between gap-x-6 gap-y-3",
		children: [/* @__PURE__ */ jsxs("div", {
			className: "min-w-0",
			children: [
				breadcrumb && /* @__PURE__ */ jsx("div", {
					className: "text-sm mb-1.5 flex items-center gap-1.5 text-c2",
					children: breadcrumb
				}),
				/* @__PURE__ */ jsx("h1", {
					className: "text-title",
					children: title
				}),
				lede && /* @__PURE__ */ jsx("p", {
					className: "text-body mt-1 max-w-2xl text-c2",
					children: lede
				})
			]
		}), actions && /* @__PURE__ */ jsx("div", {
			className: "flex shrink-0 flex-wrap items-center gap-2",
			children: actions
		})]
	});
}
var BUTTON_VARIANTS = {
	primary: "bg-brand text-on-brand border-brand hover:bg-brand-hover hover:border-brand-hover",
	secondary: "bg-raised text-c1 border-line hover:border-line-strong",
	ghost: "bg-transparent text-c2 border-transparent hover:bg-raised hover:text-c1",
	danger: "bg-transparent text-danger border-danger/45 hover:bg-danger/10"
};
var BUTTON_SIZES = {
	sm: "h-7 gap-1.5 px-2.5 text-xs",
	md: "h-9 gap-2 px-3.5 text-sm",
	lg: "h-11 gap-2 px-5 text-body"
};
function Button({ children, onClick, variant = "secondary", size = "md", disabled, busy, className, type = "button", title }) {
	return /* @__PURE__ */ jsxs("button", {
		type,
		onClick,
		disabled: disabled || busy,
		title,
		"aria-busy": busy || void 0,
		className: cx("inline-flex select-none items-center justify-center whitespace-nowrap rounded-control border font-medium transition-colors", "disabled:cursor-not-allowed disabled:opacity-45", BUTTON_VARIANTS[variant], BUTTON_SIZES[size], className),
		children: [busy && /* @__PURE__ */ jsx(Loader2, {
			size: 14,
			className: "animate-spin",
			"aria-hidden": true
		}), children]
	});
}
var CONTROL = "w-full rounded-control border border-line bg-raised px-3 text-body text-c1 outline-none transition-colors placeholder:text-c3 focus:border-brand disabled:opacity-50";
function Field({ label, hint, children, htmlFor }) {
	return /* @__PURE__ */ jsxs("div", {
		className: "min-w-0",
		children: [
			/* @__PURE__ */ jsx("label", {
				htmlFor,
				className: "label mb-1.5 block text-c3",
				children: label
			}),
			children,
			hint && /* @__PURE__ */ jsx("p", {
				className: "text-xs mt-1 text-c3",
				children: hint
			})
		]
	});
}
function Input({ label, hint, className, ...rest }) {
	const id = useId();
	return /* @__PURE__ */ jsx(Field, {
		label,
		hint,
		htmlFor: id,
		children: /* @__PURE__ */ jsx("input", {
			id,
			className: cx(CONTROL, "h-9", className),
			...rest
		})
	});
}
var STATUS_TONE = {
	malicious: "danger",
	suspicious: "warning",
	benign: "success",
	clean: "success",
	critical: "danger",
	high: "danger",
	medium: "warning",
	low: "neutral",
	running: "brand",
	awaiting_approval: "warning",
	awaiting_training: "info",
	completed: "success",
	failed: "danger",
	assigned: "info",
	in_progress: "brand",
	expired: "danger",
	new: "warning",
	in_loop: "brand",
	dismissed: "neutral",
	draft: "neutral",
	pending_review: "warning",
	approved: "success",
	rejected: "danger",
	active: "brand",
	clicked: "danger",
	reported: "success",
	ignored: "neutral",
	pending: "neutral",
	human_sensor: "brand",
	feed: "info",
	manual: "neutral"
};
var TONE_CHIP = {
	neutral: "border-line text-c2",
	brand: "border-brand/40 text-brand-fg",
	info: "border-info/40 text-info",
	success: "border-success/40 text-success",
	warning: "border-warning/40 text-warning",
	danger: "border-danger/45 text-danger"
};
var TONE_DOT = {
	neutral: "bg-c3",
	brand: "bg-brand",
	info: "bg-info",
	success: "bg-success",
	warning: "bg-warning",
	danger: "bg-danger"
};
/** Human wording for a delivery channel — the single source of truth. */
var CHANNEL_LABELS = {
	email: "Email",
	url: "URL",
	file: "File",
	sms: "SMS",
	qr: "QR code",
	chat: "Chat",
	web: "Web"
};
function humanise(value) {
	return CHANNEL_LABELS[value] ?? value.replace(/_/g, " ").replace(/^./, (c) => c.toUpperCase());
}
/**
* A state, rendered as an instrument readout rather than a filled pill: a
* coloured dot plus the word. Filled pastel pills for every value are the
* strongest "generated dashboard" signature in the interface, and at five
* badges per row they turned run lists into confetti.
*/
function Status({ value, label }) {
	const tone = STATUS_TONE[value] ?? "neutral";
	return /* @__PURE__ */ jsxs("span", {
		className: cx("inline-flex items-center gap-1.5 whitespace-nowrap rounded-chip border px-1.5 py-0.5 text-xs font-medium", TONE_CHIP[tone]),
		children: [/* @__PURE__ */ jsx("span", {
			className: cx("h-1.5 w-1.5 shrink-0 rounded-full", TONE_DOT[tone]),
			"aria-hidden": true
		}), label ?? humanise(value)]
	});
}
/** A plain descriptive tag with no state semantics (channel, IOC type, reason). */
function Chip({ children, tone = "neutral" }) {
	return /* @__PURE__ */ jsx("span", {
		className: cx("inline-flex items-center whitespace-nowrap rounded-chip border px-1.5 py-0.5 text-xs", TONE_CHIP[tone]),
		children
	});
}
function Metric({ label, value, caption, tone = "neutral", size = "md" }) {
	const valueTone = {
		neutral: "text-c1",
		brand: "text-brand-fg",
		info: "text-info",
		success: "text-success",
		warning: "text-warning",
		danger: "text-danger"
	};
	const sm = size === "sm";
	return /* @__PURE__ */ jsxs("div", {
		className: cx("rounded-control border border-hair bg-panel", sm ? "px-3 py-2.5" : "px-4 py-3.5"),
		children: [
			/* @__PURE__ */ jsx("div", {
				className: "label text-c3",
				children: label
			}),
			/* @__PURE__ */ jsx("div", {
				className: cx("mt-1 font-semibold tracking-tight", sm ? "text-h" : "text-display", valueTone[tone]),
				children: value
			}),
			caption && /* @__PURE__ */ jsx("div", {
				className: "text-xs mt-1 text-c3",
				children: caption
			})
		]
	});
}
function riskBand(score) {
	if (score >= 60) return {
		tone: "danger",
		text: "text-danger",
		bar: "bg-danger",
		label: "High"
	};
	if (score >= 40) return {
		tone: "warning",
		text: "text-warning",
		bar: "bg-warning",
		label: "Elevated"
	};
	return {
		tone: "success",
		text: "text-success",
		bar: "bg-success",
		label: "Low"
	};
}
function RiskMeter({ score, className }) {
	const band = riskBand(score);
	return /* @__PURE__ */ jsxs("span", {
		className: cx("inline-flex items-center gap-2", className),
		children: [/* @__PURE__ */ jsx("span", {
			className: "h-1 w-20 overflow-hidden rounded-full bg-sunken",
			role: "img",
			"aria-label": `Risk ${score.toFixed(0)} of 100, ${band.label.toLowerCase()}`,
			children: /* @__PURE__ */ jsx("span", {
				className: cx("block h-full rounded-full", band.bar),
				style: { width: `${Math.min(100, Math.max(0, score))}%` }
			})
		}), /* @__PURE__ */ jsx("span", {
			className: cx("text-sm font-semibold", band.text),
			children: score.toFixed(0)
		})]
	});
}
function Table({ children, minWidth = 560 }) {
	return /* @__PURE__ */ jsx("div", {
		className: "-mx-5 overflow-x-auto px-5",
		children: /* @__PURE__ */ jsx("table", {
			className: "w-full border-collapse text-body",
			style: { minWidth },
			children
		})
	});
}
function TH({ children, numeric }) {
	return /* @__PURE__ */ jsx("th", {
		scope: "col",
		className: cx("label border-b border-line pb-2 text-c3", numeric ? "text-right" : "text-left"),
		children
	});
}
function TD({ children, numeric, muted }) {
	return /* @__PURE__ */ jsx("td", {
		className: cx("border-b border-hair py-2.5 pr-4 last:pr-0", numeric && "text-right", muted && "text-c2"),
		children
	});
}
/** Raw artifact / lure text. Repeated verbatim at five call sites before this. */
function CodeBlock({ children, maxHeight = 200 }) {
	return /* @__PURE__ */ jsx("pre", {
		className: "overflow-auto whitespace-pre-wrap rounded-control border border-hair bg-sunken p-3 font-mono text-xs leading-relaxed text-c2",
		style: { maxHeight },
		children
	});
}
function Callout({ tone = "info", title, icon, actions, children }) {
	return /* @__PURE__ */ jsxs("div", {
		className: cx("rounded-control border p-3", {
			brand: "border-brand/30 bg-brand/8",
			info: "border-info/30 bg-info/8",
			success: "border-success/30 bg-success/8",
			warning: "border-warning/30 bg-warning/8",
			danger: "border-danger/35 bg-danger/8"
		}[tone]),
		children: [(title || actions) && /* @__PURE__ */ jsxs("div", {
			className: "mb-1.5 flex items-center justify-between gap-3",
			children: [/* @__PURE__ */ jsxs("span", {
				className: cx("label flex items-center gap-1.5", {
					brand: "text-brand-fg",
					info: "text-info",
					success: "text-success",
					warning: "text-warning",
					danger: "text-danger"
				}[tone]),
				children: [icon, title]
			}), actions]
		}), /* @__PURE__ */ jsx("div", {
			className: "text-sm leading-relaxed",
			children
		})]
	});
}
function Spinner({ label }) {
	return /* @__PURE__ */ jsxs("div", {
		className: "flex items-center justify-center gap-2 py-12 text-c2",
		role: "status",
		children: [/* @__PURE__ */ jsx(Loader2, {
			size: 18,
			className: "animate-spin",
			"aria-hidden": true
		}), label && /* @__PURE__ */ jsx("span", {
			className: "text-body",
			children: label
		})]
	});
}
/**
* The single place a page waits for its first payload.
*
* `usePoll` keeps `data` at null when a request fails, so a page that only
* checks `if (!data) return <Spinner/>` spins forever whenever the API is
* unreachable — hiding the one actionable message the client produces. Always
* pass the poll's `error` through here.
*/
function LoadState({ error, label, onRetry }) {
	if (!error) return /* @__PURE__ */ jsx(Spinner, { label });
	return /* @__PURE__ */ jsx("div", {
		className: "rise py-12",
		role: "alert",
		children: /* @__PURE__ */ jsxs("div", {
			className: "mx-auto flex max-w-md flex-col items-center gap-3 rounded-panel border border-danger/35 bg-danger/8 px-5 py-6 text-center",
			children: [
				/* @__PURE__ */ jsx(CircleAlert, {
					size: 22,
					className: "text-danger",
					"aria-hidden": true
				}),
				/* @__PURE__ */ jsx("p", {
					className: "text-body leading-relaxed text-danger",
					children: error
				}),
				onRetry && /* @__PURE__ */ jsxs(Button, {
					variant: "secondary",
					size: "sm",
					onClick: onRetry,
					children: [/* @__PURE__ */ jsx(RefreshCw, {
						size: 13,
						"aria-hidden": true
					}), " Try again"]
				})
			]
		})
	});
}
/**
* The counterpart to `LoadState`: the page has data, but polling has stopped
* working. Non-destructive on purpose — the last good payload stays on screen,
* captioned with the fact that it is frozen and with when it froze. A silent
* outage is the dangerous version of this: an analyst watching a queue that
* stopped updating has no way to tell it apart from a quiet queue.
*/
function StaleNotice({ error, onRetry }) {
	return /* @__PURE__ */ jsxs("div", {
		role: "status",
		className: "flex flex-wrap items-center gap-x-3 gap-y-2 rounded-control border border-warning/40 bg-warning/8 px-3 py-2",
		children: [
			/* @__PURE__ */ jsxs("span", {
				className: "label flex items-center gap-1.5 text-warning",
				children: [/* @__PURE__ */ jsx(CircleAlert, {
					size: 14,
					"aria-hidden": true
				}), " Not updating"]
			}),
			/* @__PURE__ */ jsxs("span", {
				className: "text-sm min-w-0 flex-1 text-c2",
				children: [error || "The connection to the API dropped.", " Everything below is the last data received."]
			}),
			onRetry && /* @__PURE__ */ jsxs(Button, {
				variant: "secondary",
				size: "sm",
				onClick: onRetry,
				children: [/* @__PURE__ */ jsx(RefreshCw, {
					size: 13,
					"aria-hidden": true
				}), " Retry"]
			})
		]
	});
}
function Empty({ icon, children }) {
	return /* @__PURE__ */ jsxs("div", {
		className: "rounded-control border border-dashed border-line px-4 py-10 text-center",
		children: [icon && /* @__PURE__ */ jsx("div", {
			className: "mb-2 flex justify-center text-c3",
			children: icon
		}), /* @__PURE__ */ jsx("p", {
			className: "text-sm text-c3",
			children
		})]
	});
}
/**
* Segmented filter. Rendered as a real radiogroup rather than a `tablist`: the
* old version claimed `role="tablist"` while owning no tabpanel and no
* `aria-controls`, which is a broken promise to a screen reader.
*/
function Tabs({ label, tabs, value, onChange, fill }) {
	return /* @__PURE__ */ jsx("div", {
		role: "radiogroup",
		"aria-label": label,
		className: cx("inline-flex gap-1 rounded-control border border-hair bg-panel p-1", fill && "flex w-full"),
		children: tabs.map((t) => /* @__PURE__ */ jsxs("button", {
			type: "button",
			role: "radio",
			"aria-checked": value === t.key,
			onClick: () => onChange(t.key),
			className: cx("rounded-chip px-3 py-1.5 text-sm font-medium transition-colors", fill && "flex-1", value === t.key ? "bg-raised text-c1" : "text-c2 hover:text-c1"),
			children: [t.label, t.count !== void 0 && /* @__PURE__ */ jsx("span", {
				className: "ml-1.5 text-c3",
				children: t.count
			})]
		}, t.key))
	});
}
function timeAgo(iso) {
	if (!iso) return "—";
	const normalized = /[zZ]$|[+-]\d\d:\d\d$/.test(iso) ? iso : `${iso}Z`;
	const then = new Date(normalized).getTime();
	if (Number.isNaN(then)) return "—";
	const seconds = Math.max(0, (Date.now() - then) / 1e3);
	if (seconds < 60) return `${Math.floor(seconds)}s ago`;
	if (seconds < 3600) return `${Math.floor(seconds / 60)}m ago`;
	if (seconds < 86400) return `${Math.floor(seconds / 3600)}h ago`;
	return `${Math.floor(seconds / 86400)}d ago`;
}
//#endregion
//#region src/lib/format.ts
function formatBytes(n) {
	if (n < 1024) return `${n} B`;
	if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
	if (n < 1024 * 1024 * 1024) return `${(n / (1024 * 1024)).toFixed(1)} MB`;
	return `${(n / (1024 * 1024 * 1024)).toFixed(2)} GB`;
}
/** Verdict word for a risk band, from the fixed 0-29/30-59/60-79/80-100 scale. */
function verdictWord(riskLevel) {
	switch (riskLevel) {
		case "critical": return "Critical";
		case "high": return "High risk";
		case "medium": return "Suspicious";
		default: return "Low risk";
	}
}
/** Map a risk band to the ui.tsx status tone vocabulary (risk = red/amber/green). */
function riskTone(riskLevel) {
	if (riskLevel === "critical" || riskLevel === "high") return "danger";
	if (riskLevel === "medium") return "warning";
	return "success";
}
/**
* The verdict carried by a payload, or null when there is none.
*
* The backend serialises a missing verdict as `{}`, and jobs analysed before the
* verdict engine shipped have exactly that — so an object is not enough, the
* decision itself has to be present and recognised.
*/
function verdictOf(job) {
	const v = job.verdict?.verdict;
	return v === "malicious" || v === "suspicious" || v === "clean" ? v : null;
}
function verdictTone(verdict) {
	if (verdict === "malicious") return "danger";
	if (verdict === "suspicious") return "warning";
	return "success";
}
function verdictHeadline(verdict) {
	if (verdict === "malicious") return "Malicious";
	if (verdict === "suspicious") return "Suspicious";
	return "No threat found";
}
/** The impact rating shares the severity vocabulary, so it shares the tone map. */
function impactOf(job) {
	const c = job.impact;
	return c && typeof c.base_score === "number" && c.vector ? c : null;
}
function familyLabel(family) {
	return {
		pe: "Windows executable",
		elf: "Linux binary",
		office: "Office document",
		script: "Script",
		pdf: "PDF document",
		archive: "Archive",
		apk: "Android package",
		jar: "Java archive",
		diskimage: "Disk image",
		unknown: "Unclassified"
	}[family] ?? family;
}
/** Human name for an IOC bucket. */
function iocLabel(key) {
	return {
		urls: "URLs",
		domains: "Domains",
		ips: "IP addresses",
		emails: "Email addresses",
		hashes: "Hashes",
		file_paths: "File paths",
		registry_keys: "Registry keys",
		mutexes: "Mutexes"
	}[key] ?? key;
}
//#endregion
//#region src/lib/useCountUp.ts
/**
* Ease a number from its previous value to `target` on change. Used for stat
* tiles and the score gauge so figures settle in rather than snapping. Honours
* reduced-motion by jumping straight to the target.
*/
function useCountUp(target, ms = 900) {
	const [value, setValue] = useState(target);
	const fromRef = useRef(target);
	useEffect(() => {
		const reduce = window.matchMedia?.("(prefers-reduced-motion: reduce)").matches;
		const from = fromRef.current;
		if (reduce || from === target) {
			setValue(target);
			fromRef.current = target;
			return;
		}
		let raf = 0;
		const start = performance.now();
		const tick = (now) => {
			const t = Math.min(1, (now - start) / ms);
			const eased = 1 - Math.pow(1 - t, 3);
			setValue(from + (target - from) * eased);
			if (t < 1) raf = requestAnimationFrame(tick);
			else fromRef.current = target;
		};
		raf = requestAnimationFrame(tick);
		return () => cancelAnimationFrame(raf);
	}, [target, ms]);
	return value;
}
//#endregion
//#region src/components/ScoreGauge.tsx
var TONE_STROKE = {
	danger: "stroke-danger",
	warning: "stroke-warning",
	success: "stroke-success"
};
var TONE_TEXT$2 = {
	danger: "text-danger",
	warning: "text-warning",
	success: "text-success"
};
/** A 270-degree arc gauge for the final 0-100 risk score. The arc draws itself
* in and the figure counts up on mount.
*
* `verdict`, when the job has one, outranks the score band for both colour and
* caption. The score is a magnitude and its band is not a decision: a dropper
* the engine called malicious scored 24, and the gauge drew it green and wrote
* "Low risk" underneath. */
function ScoreGauge({ score, riskLevel, verdict }) {
	const tone = verdict ? verdictTone(verdict) : riskTone(riskLevel);
	const size = 176;
	const stroke = 12;
	const r = (size - stroke) / 2;
	const cx = size / 2;
	const cy = size / 2;
	const startAngle = 135;
	const clamped = Math.max(0, Math.min(100, score));
	const shown = useCountUp(score);
	const [progress, setProgress] = useState(0);
	useEffect(() => {
		const raf = requestAnimationFrame(() => setProgress(clamped));
		return () => cancelAnimationFrame(raf);
	}, [clamped]);
	const polar = (angleDeg) => {
		const a = angleDeg * Math.PI / 180;
		return {
			x: cx + r * Math.cos(a),
			y: cy + r * Math.sin(a)
		};
	};
	const arcPath = (fromDeg, toDeg) => {
		const start = polar(fromDeg);
		const end = polar(toDeg);
		const large = toDeg - fromDeg > 180 ? 1 : 0;
		return `M ${start.x} ${start.y} A ${r} ${r} 0 ${large} 1 ${end.x} ${end.y}`;
	};
	const trackEnd = 405;
	return /* @__PURE__ */ jsxs("div", {
		className: "flex flex-col items-center",
		children: [/* @__PURE__ */ jsxs("div", {
			className: "relative",
			style: {
				width: size,
				height: size
			},
			children: [/* @__PURE__ */ jsxs("svg", {
				viewBox: `0 0 ${size} ${size}`,
				className: "h-full w-full",
				children: [/* @__PURE__ */ jsx("path", {
					d: arcPath(startAngle, trackEnd),
					className: "stroke-sunken",
					strokeWidth: stroke,
					fill: "none",
					strokeLinecap: "round"
				}), /* @__PURE__ */ jsx("path", {
					d: arcPath(startAngle, trackEnd),
					className: `gauge-arc ${TONE_STROKE[tone]}`,
					strokeWidth: stroke,
					fill: "none",
					strokeLinecap: "round",
					pathLength: 100,
					strokeDasharray: 100,
					strokeDashoffset: 100 - progress
				})]
			}), /* @__PURE__ */ jsxs("div", {
				className: "absolute inset-0 flex flex-col items-center justify-center",
				children: [/* @__PURE__ */ jsx("span", {
					className: `text-display font-semibold tabular-nums ${TONE_TEXT$2[tone]}`,
					children: Math.round(shown)
				}), /* @__PURE__ */ jsx("span", {
					className: "text-xs text-c3",
					children: "of 100"
				})]
			})]
		}), /* @__PURE__ */ jsx("span", {
			className: `label mt-1 ${TONE_TEXT$2[tone]}`,
			children: verdict ? verdictHeadline(verdict) : verdictWord(riskLevel)
		})]
	});
}
//#endregion
//#region src/components/BehaviorGraph.tsx
/**
* A behaviour timeline: what the sample did, in order, once detonated on the
* off-host worker. One lane per event kind, dots placed on a shared millisecond
* axis — the "graph visualizing file behaviours" the brief asks for. Pure SVG,
* so it themes with the rest of the instrument and needs no chart library.
*/
var KIND_TONE = {
	process: "fill-brand",
	network: "fill-danger",
	file: "fill-info",
	registry: "fill-warning",
	memory: "fill-danger",
	syscall: "fill-c3"
};
function toneFor(kind) {
	return KIND_TONE[kind] ?? "fill-c3";
}
function BehaviorGraph({ events }) {
	if (!events.length) return null;
	const sorted = [...events].sort((a, b) => a.t_ms - b.t_ms);
	const kinds = Array.from(new Set(sorted.map((e) => e.kind)));
	const maxT = Math.max(1, ...sorted.map((e) => e.t_ms));
	const padL = 88;
	const padR = 16;
	const padT = 12;
	const rowH = 30;
	const width = 720;
	const axisH = 22;
	const plotW = width - padL - padR;
	const height = padT + kinds.length * rowH + axisH;
	const x = (t) => padL + t / maxT * plotW;
	const ticks = 5;
	return /* @__PURE__ */ jsx("div", {
		className: "overflow-x-auto",
		children: /* @__PURE__ */ jsxs("svg", {
			viewBox: `0 0 ${width} ${height}`,
			className: "w-full min-w-[560px]",
			role: "img",
			"aria-label": "Behaviour timeline",
			children: [
				kinds.map((kind, i) => {
					const y = padT + i * rowH + rowH / 2;
					return /* @__PURE__ */ jsxs("g", { children: [/* @__PURE__ */ jsx("line", {
						x1: padL,
						y1: y,
						x2: width - padR,
						y2: y,
						className: "stroke-hair",
						strokeWidth: 1
					}), /* @__PURE__ */ jsx("text", {
						x: padL - 10,
						y: y + 4,
						textAnchor: "end",
						className: "fill-c2 text-[11px]",
						children: kind
					})] }, kind);
				}),
				Array.from({ length: 6 }, (_, i) => {
					const t = maxT / ticks * i;
					const xx = x(t);
					const yy = padT + kinds.length * rowH;
					return /* @__PURE__ */ jsxs("g", { children: [/* @__PURE__ */ jsx("line", {
						x1: xx,
						y1: padT,
						x2: xx,
						y2: yy,
						className: "stroke-hair",
						strokeWidth: 1,
						strokeDasharray: "2 4"
					}), /* @__PURE__ */ jsxs("text", {
						x: xx,
						y: yy + 15,
						textAnchor: "middle",
						className: "fill-c3 text-[10px]",
						children: [Math.round(t), " ms"]
					})] }, i);
				}),
				sorted.map((e, i) => {
					const laneIndex = kinds.indexOf(e.kind);
					const y = padT + laneIndex * rowH + rowH / 2;
					return /* @__PURE__ */ jsx("g", { children: /* @__PURE__ */ jsx("circle", {
						cx: x(e.t_ms),
						cy: y,
						r: 5,
						className: toneFor(e.kind),
						children: /* @__PURE__ */ jsx("title", { children: `${e.t_ms} ms · ${e.kind}: ${e.detail}` })
					}) }, i);
				})
			]
		})
	});
}
//#endregion
//#region src/lib/api.ts
var TOKEN_KEY = "csbx_session";
function getSession() {
	const raw = localStorage.getItem(TOKEN_KEY);
	if (!raw) return null;
	try {
		return JSON.parse(raw);
	} catch {
		return null;
	}
}
function setSession(session) {
	if (session) localStorage.setItem(TOKEN_KEY, JSON.stringify(session));
	else localStorage.removeItem(TOKEN_KEY);
}
var sessionCleared = /* @__PURE__ */ new Set();
function notifySessionCleared() {
	for (const listener of sessionCleared) listener();
}
var ApiError = class extends Error {
	status;
	constructor(status, message) {
		super(message);
		this.status = status;
	}
};
var API_UNREACHABLE = "Can't reach the Cyclowareness Sandbox API — make sure the backend is running on port 8000, then try again.";
function authHeader() {
	const s = getSession();
	return s ? { Authorization: `Bearer ${s.token}` } : {};
}
/**
* The API's `detail` in a sentence a person can act on.
*
* Three shapes come back: a string for an HTTPException, an ARRAY of pydantic
* validation errors for a 422, and occasionally neither. The array was passed
* to `JSON.stringify` and rendered verbatim, so a mistyped field produced
* `[{"type":"missing","loc":["body","password"],"msg":"Field required",...}]`
* in the failure callout — technically the truth, and useless to the analyst
* looking at it.
*/
function readDetail(detail) {
	if (typeof detail === "string") return detail;
	if (Array.isArray(detail)) {
		const lines = detail.map((item) => {
			if (typeof item === "string") return item;
			if (!item || typeof item !== "object") return "";
			const entry = item;
			const field = (entry.loc ?? []).filter((p) => typeof p === "string" && p !== "body" && p !== "query").join(".");
			const message = entry.msg ?? "is not valid";
			return field ? `${field}: ${message}` : message;
		}).filter(Boolean);
		if (lines.length) return lines.join("; ");
	}
	return "";
}
async function handle(res, path) {
	if (res.status === 502 || res.status === 503 || res.status === 504) throw new ApiError(res.status, API_UNREACHABLE);
	if (res.status === 401 && !path.endsWith("/auth/login")) {
		setSession(null);
		notifySessionCleared();
		throw new ApiError(401, "Your session has expired. Sign in again to continue.");
	}
	if (!res.ok) {
		let detail = res.statusText;
		try {
			detail = readDetail((await res.json()).detail) || res.statusText;
		} catch {}
		throw new ApiError(res.status, detail);
	}
	return res;
}
async function request(method, path, body) {
	let res;
	try {
		res = await fetch(path, {
			method,
			headers: {
				"Content-Type": "application/json",
				...authHeader()
			},
			body: body === void 0 ? void 0 : JSON.stringify(body)
		});
	} catch {
		throw new ApiError(0, API_UNREACHABLE);
	}
	await handle(res, path);
	return res.json();
}
var api = {
	get: (path) => request("GET", path),
	post: (path, body) => request("POST", path, body),
	put: (path, body) => request("PUT", path, body),
	/** Multipart upload — the browser sets the boundary Content-Type itself. */
	async upload(path, form) {
		let res;
		try {
			res = await fetch(path, {
				method: "POST",
				headers: authHeader(),
				body: form
			});
		} catch {
			throw new ApiError(0, API_UNREACHABLE);
		}
		await handle(res, path);
		return res.json();
	},
	/** Authenticated download — fetch with the token, then save the blob. */
	async download(path, filename) {
		let res;
		try {
			res = await fetch(path, { headers: authHeader() });
		} catch {
			throw new ApiError(0, API_UNREACHABLE);
		}
		await handle(res, path);
		const blob = await res.blob();
		const url = URL.createObjectURL(blob);
		const a = document.createElement("a");
		a.href = url;
		a.download = filename;
		document.body.appendChild(a);
		a.click();
		a.remove();
		URL.revokeObjectURL(url);
	}
};
//#endregion
//#region __probe__/stubPoll.ts
function usePoll(_fetcher, _intervalMs, _deps) {
	const g = globalThis;
	return {
		data: g.__POLL__ ?? null,
		error: g.__ERR__ ?? null,
		status: g.__STATUS__ ?? null,
		stale: Boolean(g.__STALE__),
		refresh: async () => {}
	};
}
//#endregion
//#region src/pages/JobDetail.tsx
var SEVERITY_ORDER = {
	critical: 4,
	high: 3,
	medium: 2,
	low: 1,
	info: 0
};
var SEVERITY_TONE = {
	critical: "danger",
	high: "danger",
	medium: "warning",
	low: "neutral",
	info: "neutral"
};
var TONE_TEXT$1 = {
	danger: "text-danger",
	warning: "text-warning",
	success: "text-success"
};
/** Long form of the impact-rating metric letters, so the vector is readable. */
var IMPACT_METRIC = {
	AV: "Attack vector",
	AC: "Attack complexity",
	PR: "Privileges required",
	UI: "User interaction",
	S: "Scope",
	C: "Confidentiality",
	I: "Integrity",
	A: "Availability"
};
/** ATT&CK reads by tactic, not as a flat list of technique IDs. */
function byTactic(techniques) {
	const groups = /* @__PURE__ */ new Map();
	for (const t of techniques) {
		const list = groups.get(t.tactic);
		if (list) list.push(t);
		else groups.set(t.tactic, [t]);
	}
	return Array.from(groups.entries());
}
function signalsOf(job) {
	const out = [];
	for (const [name, payload] of Object.entries(job.analysis || {})) {
		if (!payload?.ran) continue;
		for (const s of payload.signals || []) out.push({
			...s,
			analyzer: name
		});
	}
	out.sort((a, b) => (SEVERITY_ORDER[b.severity] ?? 0) - (SEVERITY_ORDER[a.severity] ?? 0));
	return out;
}
function JobDetail() {
	const { id = "" } = useParams();
	const { data: job, error, stale, refresh } = usePoll(() => api.get(`/api/result/${id}`), 2e3, [id]);
	const [password, setPassword] = useState("");
	const [busy, setBusy] = useState(null);
	const [actionError, setActionError] = useState(null);
	/**
	* Every button on this page goes through here. It used to be try/finally with
	* no catch, so a rejected promise cleared the spinner and vanished: a wrong
	* archive password (422), a re-analyse on a job that is already running (409)
	* and an export of a report that no longer exists (404) all looked exactly
	* like success. The failure has to be shown, and it has to survive the next
	* poll tick — hence state, not a toast.
	*/
	async function action(name, fn) {
		setBusy(name);
		setActionError(null);
		try {
			await fn();
			await refresh();
		} catch (e) {
			setActionError(e instanceof Error ? e.message : String(e));
		} finally {
			setBusy(null);
		}
	}
	if (!job) return /* @__PURE__ */ jsxs("div", {
		className: "space-y-6",
		children: [/* @__PURE__ */ jsxs(Link, {
			to: "/queue",
			className: "text-sm inline-flex items-center gap-1.5 text-c2 hover:text-c1",
			children: [/* @__PURE__ */ jsx(ArrowLeft, {
				size: 15,
				"aria-hidden": true
			}), " Queue"]
		}), /* @__PURE__ */ jsx(LoadState, {
			error,
			label: "Loading analysis",
			onRetry: refresh
		})]
	});
	const running = job.status === "running" || job.status === "queued";
	const done = job.status === "completed";
	const signals = signalsOf(job);
	const staticTier = job.tiers?.static;
	const dynamicTier = job.tiers?.dynamic;
	const model = job.score_breakdown?.model;
	const rule = job.score_breakdown?.rule;
	const iocEntries = Object.entries(job.iocs || {}).filter(([, v]) => v && v.length);
	const yaraHits = job.analysis?.yara?.ran && job.analysis.yara.signals || [];
	const filename = job.original_name || "sample";
	const verdict = verdictOf(job);
	const detection = verdict ? job.verdict ?? null : null;
	const impact = impactOf(job);
	const mitre = Array.isArray(job.mitre) ? job.mitre : [];
	return /* @__PURE__ */ jsxs("div", {
		className: "space-y-6",
		children: [
			/* @__PURE__ */ jsxs("div", {
				className: "flex flex-wrap items-center justify-between gap-3",
				children: [/* @__PURE__ */ jsxs(Link, {
					to: "/queue",
					className: "text-sm inline-flex items-center gap-1.5 text-c2 hover:text-c1",
					children: [/* @__PURE__ */ jsx(ArrowLeft, {
						size: 15,
						"aria-hidden": true
					}), " Queue"]
				}), done && /* @__PURE__ */ jsxs("div", {
					className: "flex flex-wrap items-center gap-2",
					children: [
						/* @__PURE__ */ jsxs(Button, {
							size: "sm",
							busy: busy === "json",
							onClick: () => action("json", () => api.download(`/api/jobs/${id}/export.json`, `sandbox-${filename}.json`)),
							children: [/* @__PURE__ */ jsx(Braces, {
								size: 14,
								"aria-hidden": true
							}), " JSON"]
						}),
						/* @__PURE__ */ jsxs(Button, {
							size: "sm",
							busy: busy === "stix",
							onClick: () => action("stix", () => api.download(`/api/jobs/${id}/export.stix`, `sandbox-${filename}.stix.json`)),
							children: [/* @__PURE__ */ jsx(Share2, {
								size: 14,
								"aria-hidden": true
							}), " STIX"]
						}),
						/* @__PURE__ */ jsxs(Button, {
							size: "sm",
							busy: busy === "pdf",
							onClick: () => action("pdf", () => api.download(`/api/jobs/${id}/export.pdf`, `sandbox-${filename}.pdf`)),
							children: [/* @__PURE__ */ jsx(Download, {
								size: 14,
								"aria-hidden": true
							}), " PDF"]
						}),
						/* @__PURE__ */ jsxs(Button, {
							size: "sm",
							busy: busy === "signed",
							onClick: () => action("signed", () => api.download(`/api/jobs/${id}/export.signed`, `sandbox-${filename}.signed.json`)),
							title: "Ed25519-signed evidence copy a recipient can verify without trusting us",
							children: [/* @__PURE__ */ jsx(ShieldCheck, {
								size: 14,
								"aria-hidden": true
							}), " Signed"]
						}),
						/* @__PURE__ */ jsxs(Button, {
							size: "sm",
							busy: busy === "incident",
							onClick: () => action("incident", () => api.download(`/api/jobs/${id}/export.incident`, `sandbox-${filename}.incident.json`)),
							title: "Regulatory incident record (NIS2 Article 23 / DORA Article 19)",
							children: [/* @__PURE__ */ jsx(Siren, {
								size: 14,
								"aria-hidden": true
							}), " Incident"]
						}),
						/* @__PURE__ */ jsxs(Button, {
							size: "sm",
							busy: busy === "re",
							onClick: () => action("re", () => api.post(`/api/jobs/${id}/reanalyze`)),
							children: [/* @__PURE__ */ jsx(RefreshCw, {
								size: 14,
								"aria-hidden": true
							}), " Re-analyse"]
						})
					]
				})]
			}),
			/* @__PURE__ */ jsx(PageHeader, {
				title: /* @__PURE__ */ jsx("span", {
					className: "break-all",
					children: filename
				}),
				lede: /* @__PURE__ */ jsx("span", {
					className: "tech text-c3",
					children: job.sha256
				}),
				actions: /* @__PURE__ */ jsx(Status, { value: job.status })
			}),
			actionError && /* @__PURE__ */ jsx(Callout, {
				tone: "danger",
				title: "That action did not go through",
				children: actionError
			}),
			stale && /* @__PURE__ */ jsx(StaleNotice, {
				error,
				onRetry: refresh
			}),
			/* @__PURE__ */ jsxs("div", {
				className: "flex flex-wrap gap-x-6 gap-y-1 text-sm text-c2",
				children: [
					/* @__PURE__ */ jsx("span", { children: familyLabel(job.family) }),
					/* @__PURE__ */ jsx("span", { children: formatBytes(job.size_bytes) }),
					/* @__PURE__ */ jsx("span", { children: job.mime || "unknown type" }),
					/* @__PURE__ */ jsx("span", { children: job.source === "url" ? "From URL" : "Uploaded" }),
					/* @__PURE__ */ jsxs("span", { children: ["Submitted ", timeAgo(job.created_at)] }),
					job.submitted_by && /* @__PURE__ */ jsxs("span", { children: ["by ", job.submitted_by] })
				]
			}),
			job.status === "awaiting_password" && /* @__PURE__ */ jsx(Panel, {
				tone: "feature",
				children: /* @__PURE__ */ jsxs("div", {
					className: "flex items-start gap-3",
					children: [/* @__PURE__ */ jsx(Lock, {
						size: 20,
						className: "mt-0.5 shrink-0 text-brand-fg",
						"aria-hidden": true
					}), /* @__PURE__ */ jsxs("div", {
						className: "w-full",
						children: [
							/* @__PURE__ */ jsx("h2", {
								className: "text-h",
								children: "This archive is encrypted"
							}),
							job.error ? /* @__PURE__ */ jsxs("p", {
								className: "text-sm mt-1 text-warning",
								children: [job.error, " Try another one."]
							}) : /* @__PURE__ */ jsx("p", {
								className: "text-sm mt-1 text-c2",
								children: "Provide the password to continue. It is used once and never stored — the engine does not brute-force."
							}),
							/* @__PURE__ */ jsxs("form", {
								className: "mt-3 flex flex-wrap items-end gap-3",
								onSubmit: (e) => {
									e.preventDefault();
									action("pw", () => api.post(`/api/jobs/${id}/password`, { password }));
								},
								children: [/* @__PURE__ */ jsx("div", {
									className: "min-w-[220px] flex-1",
									children: /* @__PURE__ */ jsx(Input, {
										label: "Archive password",
										type: "password",
										value: password,
										onChange: (e) => setPassword(e.target.value)
									})
								}), /* @__PURE__ */ jsx(Button, {
									type: "submit",
									variant: "primary",
									busy: busy === "pw",
									disabled: !password,
									children: "Unlock and analyse"
								})]
							})
						]
					})]
				})
			}),
			job.status === "failed" && /* @__PURE__ */ jsx(Callout, {
				tone: "danger",
				title: "Analysis failed",
				children: job.error || "The job did not complete. Re-analyse to try again."
			}),
			job.status !== "failed" && job.error && /* @__PURE__ */ jsxs(Callout, {
				tone: "warning",
				title: "This analysis is incomplete",
				children: [job.error, " The verdict below rests on the tiers that did run."]
			}),
			running && /* @__PURE__ */ jsx(Panel, { children: /* @__PURE__ */ jsxs("div", {
				className: cx("relative flex items-center gap-3 overflow-hidden", !stale && "scan"),
				children: [/* @__PURE__ */ jsx("div", {
					className: cx("h-2 w-2 rounded-full", stale ? "bg-warning" : "bg-brand breathe"),
					"aria-hidden": true
				}), /* @__PURE__ */ jsx("span", {
					className: "text-body text-c2",
					children: stale ? /* @__PURE__ */ jsxs(Fragment, { children: [
						"Progress unknown — last seen at",
						" ",
						/* @__PURE__ */ jsx("span", {
							className: "text-c1",
							children: job.stage || job.status
						})
					] }) : /* @__PURE__ */ jsxs(Fragment, { children: ["Analysing — ", /* @__PURE__ */ jsx("span", {
						className: "text-c1",
						children: job.stage || job.status
					})] })
				})]
			}) }),
			done && /* @__PURE__ */ jsxs(Fragment, { children: [
				/* @__PURE__ */ jsx(Panel, {
					tone: "feature",
					children: /* @__PURE__ */ jsxs("div", {
						className: "grid gap-6 lg:grid-cols-[1fr_auto] lg:items-center",
						children: [/* @__PURE__ */ jsxs("div", {
							className: "min-w-0",
							children: [verdict ? /* @__PURE__ */ jsxs(Fragment, { children: [
								/* @__PURE__ */ jsx("p", {
									className: cx("label", TONE_TEXT$1[verdictTone(verdict)]),
									children: verdictHeadline(verdict)
								}),
								/* @__PURE__ */ jsx("h2", {
									className: cx("text-display mt-1 break-words", TONE_TEXT$1[verdictTone(verdict)]),
									children: (detection?.threat_name || filename).replace(/\./g, ".​")
								}),
								/* @__PURE__ */ jsxs("p", {
									className: "text-body mt-1.5 text-c2",
									children: [
										/* @__PURE__ */ jsx("span", {
											className: "font-semibold text-c1",
											children: detection?.detection_ratio
										}),
										" ",
										"detection engines flagged this sample.",
										detection?.category ? ` Classified as ${detection.category} on ${detection.platform}.` : ""
									]
								})
							] }) : /* @__PURE__ */ jsxs(Fragment, { children: [
								/* @__PURE__ */ jsx("p", {
									className: "label text-c3",
									children: "No verdict recorded"
								}),
								/* @__PURE__ */ jsx("h2", {
									className: "text-title mt-1 text-c1",
									children: "This report predates the verdict engine"
								}),
								/* @__PURE__ */ jsx("p", {
									className: "text-body mt-1.5 text-c2",
									children: "Re-analyse the sample to classify it. Until then the risk score is all this job carries, and a low score is not a clean verdict."
								})
							] }), impact && /* @__PURE__ */ jsxs("div", {
								className: "mt-3 flex flex-wrap items-center gap-2",
								children: [/* @__PURE__ */ jsxs(Chip, {
									tone: SEVERITY_TONE[impact.severity] ?? "neutral",
									children: [
										"Impact ",
										impact.base_score.toFixed(1),
										" ",
										impact.severity
									]
								}), /* @__PURE__ */ jsx("span", {
									className: "tech text-c3",
									children: impact.vector
								})]
							})]
						}), /* @__PURE__ */ jsx("div", {
							className: "justify-self-center lg:w-64",
							children: /* @__PURE__ */ jsx(ScoreGauge, {
								score: job.final_score,
								riskLevel: job.risk_level,
								verdict
							})
						})]
					})
				}),
				detection && detection.engines?.length > 0 && /* @__PURE__ */ jsx(Panel, {
					title: "Detection engines",
					subtitle: `${detection.detection_ratio} flagged this sample`,
					children: /* @__PURE__ */ jsx("div", {
						className: "divide-hair -my-2",
						children: [...detection.engines].sort((a, b) => Number(b.detected) - Number(a.detected)).map((e, i) => /* @__PURE__ */ jsxs("div", {
							className: "flex items-center justify-between gap-3 py-2",
							children: [/* @__PURE__ */ jsx("span", {
								className: "tech min-w-0 flex-1 truncate text-c2",
								children: e.engine
							}), e.detected ? /* @__PURE__ */ jsxs("span", {
								className: "flex shrink-0 items-center gap-2",
								children: [/* @__PURE__ */ jsx("span", {
									className: "text-sm font-medium text-c1",
									children: e.result
								}), /* @__PURE__ */ jsx(Chip, {
									tone: SEVERITY_TONE[e.severity] ?? "neutral",
									children: e.severity
								})]
							}) : /* @__PURE__ */ jsx("span", {
								className: "text-sm shrink-0 text-c3",
								children: "Undetected"
							})]
						}, `${e.engine}-${i}`))
					})
				}),
				/* @__PURE__ */ jsxs("div", {
					className: "grid gap-6 lg:grid-cols-2",
					children: [/* @__PURE__ */ jsx(Panel, {
						title: "Cyclowareness Impact Rating",
						subtitle: "Severity of what this sample can do, not of the file",
						children: impact ? /* @__PURE__ */ jsxs("div", {
							className: "space-y-3",
							children: [
								/* @__PURE__ */ jsxs("div", {
									className: "flex items-baseline gap-3",
									children: [/* @__PURE__ */ jsx("span", {
										className: cx("text-display font-semibold tabular-nums", TONE_TEXT$1[SEVERITY_TONE[impact.severity] ?? "neutral"] ?? "text-c1"),
										children: impact.base_score.toFixed(1)
									}), /* @__PURE__ */ jsx(Chip, {
										tone: SEVERITY_TONE[impact.severity] ?? "neutral",
										children: impact.severity
									})]
								}),
								/* @__PURE__ */ jsx("p", {
									className: "tech text-c3",
									children: impact.vector
								}),
								/* @__PURE__ */ jsx("div", {
									className: "flex flex-wrap gap-1.5",
									children: Object.entries(impact.metrics || {}).map(([m, v]) => /* @__PURE__ */ jsxs(Chip, {
										tone: "neutral",
										children: [
											IMPACT_METRIC[m] ?? m,
											": ",
											v
										]
									}, m))
								}),
								(impact.rationale || []).length > 0 && /* @__PURE__ */ jsx("div", {
									className: "space-y-1.5 border-t border-hair pt-3",
									children: impact.rationale.map((r, i) => /* @__PURE__ */ jsxs("p", {
										className: "text-sm text-c2",
										children: [
											/* @__PURE__ */ jsxs("span", {
												className: "tech text-c1",
												children: [
													r.metric,
													":",
													r.value
												]
											}),
											" ",
											r.why
										]
									}, i))
								}),
								/* @__PURE__ */ jsx("p", {
									className: "text-sm border-t border-hair pt-3 text-c3",
									children: impact.disclaimer ?? "Derived from the capabilities this sample was observed to have. Not a vulnerability score, and not CVSS — the arithmetic is CVSS-compatible so the 0-10 scale reads as expected."
								})
							]
						}) : /* @__PURE__ */ jsx("p", {
							className: "text-sm text-c2",
							children: "No impact rating on this job — it was analysed before the scoring engine shipped."
						})
					}), /* @__PURE__ */ jsx(Panel, {
						title: "MITRE ATT&CK",
						subtitle: `${mitre.length} technique${mitre.length === 1 ? "" : "s"} mapped from observed evidence`,
						children: mitre.length === 0 ? /* @__PURE__ */ jsx("p", {
							className: "text-sm text-c2",
							children: "No technique was evidenced. A technique is only claimed when a signal supports it."
						}) : /* @__PURE__ */ jsx("div", {
							className: "space-y-4",
							children: byTactic(mitre).map(([tactic, techniques]) => /* @__PURE__ */ jsxs("div", { children: [/* @__PURE__ */ jsx(GroupLabel, { children: tactic }), /* @__PURE__ */ jsx("div", {
								className: "space-y-2",
								children: techniques.map((t) => /* @__PURE__ */ jsxs("div", {
									className: "min-w-0",
									children: [/* @__PURE__ */ jsxs("p", {
										className: "text-body font-medium text-c1",
										children: [
											/* @__PURE__ */ jsx("span", {
												className: "tech text-brand-fg",
												children: t.technique_id
											}),
											" ",
											t.name
										]
									}), t.evidence?.length > 0 && /* @__PURE__ */ jsx("p", {
										className: "tech text-c3",
										children: t.evidence.join(", ")
									})]
								}, t.technique_id))
							})] }, tactic))
						})
					})]
				}),
				/* @__PURE__ */ jsx(Panel, {
					title: "Why this score",
					children: /* @__PURE__ */ jsxs("div", {
						className: "space-y-3",
						children: [(job.score_breakdown?.top_reasons || []).length === 0 ? /* @__PURE__ */ jsx("p", {
							className: "text-sm text-c2",
							children: "No suspicious indicators were found by the analyzers that ran. This is a “nothing found” result, not a guarantee of safety."
						}) : (job.score_breakdown?.top_reasons || []).map((r) => /* @__PURE__ */ jsxs("div", {
							className: "flex items-start gap-2.5",
							children: [/* @__PURE__ */ jsx(Chip, {
								tone: SEVERITY_TONE[r.severity] ?? "neutral",
								children: r.severity
							}), /* @__PURE__ */ jsxs("div", {
								className: "min-w-0",
								children: [/* @__PURE__ */ jsx("p", {
									className: "text-body font-medium text-c1",
									children: r.title
								}), r.detail && /* @__PURE__ */ jsx("p", {
									className: "text-sm text-c2",
									children: r.detail
								})]
							})]
						}, r.id)), /* @__PURE__ */ jsxs("div", {
							className: "mt-2 flex flex-wrap gap-2 border-t border-hair pt-3 text-sm text-c2",
							children: [
								/* @__PURE__ */ jsxs("span", { children: ["Rule component ", /* @__PURE__ */ jsx("span", {
									className: "font-semibold text-c1",
									children: job.rule_score.toFixed(0)
								})] }),
								/* @__PURE__ */ jsx("span", {
									className: "text-c3",
									children: "·"
								}),
								/* @__PURE__ */ jsxs("span", { children: ["Model component ", /* @__PURE__ */ jsx("span", {
									className: "font-semibold text-c1",
									children: job.ai_score.toFixed(0)
								})] }),
								job.score_breakdown?.formula && /* @__PURE__ */ jsx("span", {
									className: "tech text-c3",
									children: job.score_breakdown.formula
								})
							]
						})]
					})
				}),
				/* @__PURE__ */ jsx(Panel, {
					title: "Analysis tiers",
					children: /* @__PURE__ */ jsxs("div", {
						className: "grid gap-3 sm:grid-cols-2",
						children: [/* @__PURE__ */ jsxs("div", {
							className: "rounded-control border border-hair bg-raised p-3",
							children: [/* @__PURE__ */ jsxs("div", {
								className: "flex items-center justify-between",
								children: [/* @__PURE__ */ jsx("span", {
									className: "label text-c3",
									children: "Static"
								}), /* @__PURE__ */ jsx(Status, {
									value: staticTier?.ran ? "completed" : "failed",
									label: staticTier?.ran ? "Ran" : "Did not run"
								})]
							}), /* @__PURE__ */ jsx("p", {
								className: "text-sm mt-1.5 text-c2",
								children: staticTier?.detail || "Parsers and YARA. The sample is never executed."
							})]
						}), /* @__PURE__ */ jsxs("div", {
							className: "rounded-control border border-hair bg-raised p-3",
							children: [/* @__PURE__ */ jsxs("div", {
								className: "flex items-center justify-between",
								children: [/* @__PURE__ */ jsx("span", {
									className: "label text-c3",
									children: "Dynamic"
								}), /* @__PURE__ */ jsx(Status, {
									value: dynamicTier?.ran ? "completed" : "pending",
									label: dynamicTier?.ran ? `Ran (${dynamicTier.engine})` : "Not run"
								})]
							}), /* @__PURE__ */ jsx("p", {
								className: "text-sm mt-1.5 text-c2",
								children: dynamicTier?.detail || "No isolated worker was attached, so the sample was not detonated — only statically analysed."
							})]
						})]
					})
				}),
				job.dynamic?.ran && job.dynamic.timeline && job.dynamic.timeline.length > 0 && /* @__PURE__ */ jsxs(Panel, {
					title: "Observed behaviour",
					subtitle: `Detonated on the ${job.dynamic.engine} engine (${job.dynamic.worker})`,
					children: [/* @__PURE__ */ jsx(BehaviorGraph, { events: job.dynamic.timeline }), job.dynamic.signals && job.dynamic.signals.length > 0 && /* @__PURE__ */ jsx("div", {
						className: "mt-4 space-y-2",
						children: job.dynamic.signals.map((s, i) => /* @__PURE__ */ jsxs("div", {
							className: "flex items-start gap-2.5",
							children: [/* @__PURE__ */ jsx(Chip, {
								tone: SEVERITY_TONE[s.severity] ?? "neutral",
								children: s.severity
							}), /* @__PURE__ */ jsxs("div", {
								className: "min-w-0",
								children: [/* @__PURE__ */ jsx("p", {
									className: "text-body font-medium text-c1",
									children: s.title
								}), s.detail && /* @__PURE__ */ jsx("p", {
									className: "text-sm text-c2",
									children: s.detail
								})]
							})]
						}, i))
					})]
				}),
				/* @__PURE__ */ jsx(Panel, {
					title: "Signals",
					subtitle: `${signals.length} observation${signals.length === 1 ? "" : "s"} across all analyzers`,
					children: signals.length === 0 ? /* @__PURE__ */ jsx("p", {
						className: "text-sm text-c2",
						children: "No signals fired."
					}) : /* @__PURE__ */ jsx("div", {
						className: "divide-hair -my-2",
						children: signals.map((s, i) => /* @__PURE__ */ jsxs("div", {
							className: "flex items-start gap-3 py-2.5",
							children: [/* @__PURE__ */ jsx(Chip, {
								tone: SEVERITY_TONE[s.severity] ?? "neutral",
								children: s.severity
							}), /* @__PURE__ */ jsxs("div", {
								className: "min-w-0 flex-1",
								children: [/* @__PURE__ */ jsxs("div", {
									className: "flex flex-wrap items-baseline gap-x-2",
									children: [/* @__PURE__ */ jsx("span", {
										className: "text-body font-medium text-c1",
										children: s.title
									}), /* @__PURE__ */ jsx("span", {
										className: "tech text-c3",
										children: s.id
									})]
								}), s.detail && /* @__PURE__ */ jsx("p", {
									className: "text-sm mt-0.5 text-c2",
									children: s.detail
								})]
							})]
						}, `${s.id}-${i}`))
					})
				}),
				/* @__PURE__ */ jsxs("div", {
					className: "grid gap-6 lg:grid-cols-2",
					children: [/* @__PURE__ */ jsx(Panel, {
						title: "Rule component",
						subtitle: "Severity-weighted, saturating per band",
						children: rule && rule.bands.length > 0 ? /* @__PURE__ */ jsxs("div", {
							className: "space-y-2",
							children: [rule.bands.map((b) => /* @__PURE__ */ jsxs("div", {
								className: "flex items-center justify-between text-sm",
								children: [/* @__PURE__ */ jsxs("span", {
									className: "flex items-center gap-2",
									children: [/* @__PURE__ */ jsx(Chip, {
										tone: SEVERITY_TONE[b.severity] ?? "neutral",
										children: b.severity
									}), /* @__PURE__ */ jsxs("span", {
										className: "text-c2",
										children: [
											b.count,
											" signal",
											b.count === 1 ? "" : "s"
										]
									})]
								}), /* @__PURE__ */ jsxs("span", {
									className: "tabular-nums font-medium text-c1",
									children: ["+", b.contribution.toFixed(1)]
								})]
							}, b.severity)), /* @__PURE__ */ jsxs("div", {
								className: "mt-2 flex justify-between border-t border-hair pt-2 text-sm",
								children: [/* @__PURE__ */ jsx("span", {
									className: "text-c2",
									children: "Rule score"
								}), /* @__PURE__ */ jsx("span", {
									className: "tabular-nums font-semibold text-c1",
									children: rule.score.toFixed(1)
								})]
							})]
						}) : /* @__PURE__ */ jsx("p", {
							className: "text-sm text-c2",
							children: "No rule signals contributed."
						})
					}), /* @__PURE__ */ jsx(Panel, {
						title: "Model component",
						subtitle: "Expert-weighted logistic, per-feature contributions",
						children: model && model.contributions.length > 0 ? /* @__PURE__ */ jsxs("div", {
							className: "space-y-2",
							children: [model.contributions.map((c) => /* @__PURE__ */ jsxs("div", { children: [/* @__PURE__ */ jsxs("div", {
								className: "flex items-center justify-between text-sm",
								children: [/* @__PURE__ */ jsx("span", {
									className: "text-c2",
									children: c.feature.replace(/_/g, " ")
								}), /* @__PURE__ */ jsxs("span", {
									className: "tabular-nums text-c3",
									children: [
										"×",
										c.weight,
										" · +",
										c.contribution.toFixed(2)
									]
								})]
							}), /* @__PURE__ */ jsx("div", {
								className: "mt-1 h-1 overflow-hidden rounded-full bg-sunken",
								children: /* @__PURE__ */ jsx("div", {
									className: "h-full rounded-full bg-brand",
									style: { width: `${Math.min(100, c.value * 100)}%` }
								})
							})] }, c.feature)), /* @__PURE__ */ jsx("p", {
								className: "text-xs mt-2 text-c3",
								children: model.provenance
							})]
						}) : /* @__PURE__ */ jsxs("p", {
							className: "text-sm text-c2",
							children: [
								"The model found no contributing features (score near the ",
								model?.bias ?? "−",
								" bias floor)."
							]
						})
					})]
				}),
				/* @__PURE__ */ jsxs("div", {
					className: "grid gap-6 lg:grid-cols-2",
					children: [/* @__PURE__ */ jsx(Panel, {
						title: "YARA matches",
						subtitle: `${yaraHits.length} rule${yaraHits.length === 1 ? "" : "s"} matched`,
						children: yaraHits.length === 0 ? /* @__PURE__ */ jsx("p", {
							className: "text-sm text-c2",
							children: "No YARA rules matched."
						}) : /* @__PURE__ */ jsx("div", {
							className: "space-y-2",
							children: yaraHits.map((h, i) => /* @__PURE__ */ jsxs("div", {
								className: "flex items-start gap-2.5",
								children: [/* @__PURE__ */ jsx(Chip, {
									tone: SEVERITY_TONE[h.severity] ?? "neutral",
									children: h.severity
								}), /* @__PURE__ */ jsxs("div", {
									className: "min-w-0",
									children: [/* @__PURE__ */ jsx("p", {
										className: "text-body font-medium text-c1",
										children: h.title
									}), h.detail && /* @__PURE__ */ jsx("p", {
										className: "text-sm text-c2",
										children: h.detail
									})]
								})]
							}, i))
						})
					}), /* @__PURE__ */ jsx(Panel, {
						title: "Indicators of compromise",
						subtitle: iocEntries.length ? void 0 : "None extracted",
						children: iocEntries.length === 0 ? /* @__PURE__ */ jsx("p", {
							className: "text-sm text-c2",
							children: "No indicators were extracted from this sample."
						}) : /* @__PURE__ */ jsx("div", {
							className: "space-y-3",
							children: iocEntries.map(([key, values]) => /* @__PURE__ */ jsxs("div", { children: [/* @__PURE__ */ jsx(GroupLabel, { children: iocLabel(key) }), /* @__PURE__ */ jsx("div", {
								className: "space-y-1",
								children: values.map((v) => /* @__PURE__ */ jsx("div", {
									className: "tech rounded-chip bg-sunken px-2 py-1 text-c2",
									children: v
								}, v))
							})] }, key))
						})
					})]
				}),
				job.children && job.children.length > 0 && /* @__PURE__ */ jsx(Panel, {
					title: "Archive contents",
					subtitle: "An archive is as dangerous as its worst member",
					children: /* @__PURE__ */ jsx("div", {
						className: "divide-hair -my-2",
						children: job.children.map((c) => /* @__PURE__ */ jsxs(Link, {
							to: `/job/${c.public_id}`,
							className: "flex items-center justify-between gap-3 py-2.5 transition-colors hover:bg-raised",
							children: [/* @__PURE__ */ jsxs("div", {
								className: "min-w-0",
								children: [/* @__PURE__ */ jsx("p", {
									className: "truncate text-body text-c1",
									children: c.original_name || c.sha256.slice(0, 16)
								}), /* @__PURE__ */ jsx("p", {
									className: "tech text-c3",
									children: familyLabel(c.family)
								})]
							}), /* @__PURE__ */ jsxs("div", {
								className: "flex items-center gap-3",
								children: [
									/* @__PURE__ */ jsx(Status, { value: c.status }),
									/* @__PURE__ */ jsx("span", {
										className: "tabular-nums text-sm font-semibold text-c1",
										children: c.final_score.toFixed(0)
									}),
									/* @__PURE__ */ jsx(ChevronRight, {
										size: 16,
										className: "text-c3",
										"aria-hidden": true
									})
								]
							})]
						}, c.public_id))
					})
				}),
				/* @__PURE__ */ jsx(Panel, {
					title: "Analyst feedback",
					subtitle: "Dispute the verdict — it feeds the reanalysis loop",
					children: /* @__PURE__ */ jsxs("div", {
						className: "flex flex-wrap items-center gap-3",
						children: [
							/* @__PURE__ */ jsxs(Button, {
								variant: job.feedback === "false_positive" ? "primary" : "secondary",
								busy: busy === "fp",
								onClick: () => action("fp", () => api.post(`/api/jobs/${id}/feedback`, { verdict: "false_positive" })),
								children: [/* @__PURE__ */ jsx(Flag, {
									size: 14,
									"aria-hidden": true
								}), " Mark false positive"]
							}),
							/* @__PURE__ */ jsxs(Button, {
								variant: job.feedback === "true_positive" ? "primary" : "secondary",
								busy: busy === "tp",
								onClick: () => action("tp", () => api.post(`/api/jobs/${id}/feedback`, { verdict: "true_positive" })),
								children: [/* @__PURE__ */ jsx(FileText, {
									size: 14,
									"aria-hidden": true
								}), " Confirm true positive"]
							}),
							job.feedback && /* @__PURE__ */ jsxs("span", {
								className: "text-sm text-c2",
								children: ["Recorded: ", job.feedback === "false_positive" ? "false positive" : "true positive"]
							})
						]
					})
				}),
				/* @__PURE__ */ jsx(Panel, {
					title: "Raw analysis payload",
					tone: "quiet",
					children: /* @__PURE__ */ jsx(CodeBlock, {
						maxHeight: 280,
						children: JSON.stringify(job.analysis, null, 2)
					})
				})
			] })
		]
	});
}
//#endregion
//#region src/lib/chart.ts
function cssVar(name) {
	if (typeof window === "undefined") return "";
	return getComputedStyle(document.documentElement).getPropertyValue(name).trim();
}
/**
* Verdict colours. Separate from `riskColors` because a verdict is not a score
* band: a sample can be called malicious at a score of 24, and colouring it by
* the band would paint that slice green.
*/
function verdictColors() {
	return {
		malicious: cssVar("--color-danger"),
		suspicious: cssVar("--color-warning"),
		clean: cssVar("--color-success"),
		unclassified: cssVar("--color-c3")
	};
}
function brandColor() {
	return cssVar("--color-brand");
}
//#endregion
//#region src/components/Charts.tsx
function TooltipBox({ active, payload }) {
	if (!active || !payload?.length) return null;
	const p = payload[0];
	return /* @__PURE__ */ jsxs("div", {
		className: "rounded-control border border-line bg-panel px-2.5 py-1.5 text-xs shadow-lg",
		children: [/* @__PURE__ */ jsxs("span", {
			className: "text-c2",
			children: [p.payload?.label ?? p.name, ": "]
		}), /* @__PURE__ */ jsx("span", {
			className: "font-semibold tabular-nums text-c1",
			children: p.value
		})]
	});
}
/**
* Verdict distribution as a donut. Verdicts use the reserved status palette
* (red/amber/green), never the brand accent, and every slice is also named in
* the legend so identity is never colour-alone.
*/
function VerdictDonut({ slices, total }) {
	const colors = verdictColors();
	const data = slices.filter((s) => s.value > 0);
	const panel = cssVar("--color-panel");
	return /* @__PURE__ */ jsxs("div", {
		className: "flex flex-col items-center gap-4 sm:flex-row sm:gap-6",
		children: [/* @__PURE__ */ jsxs("div", {
			className: "relative h-[180px] w-[180px] shrink-0",
			children: [/* @__PURE__ */ jsx(ResponsiveContainer, {
				width: "100%",
				height: "100%",
				children: /* @__PURE__ */ jsxs(PieChart, { children: [/* @__PURE__ */ jsx(Pie, {
					data: data.length ? data : [{
						key: "empty",
						label: "No data",
						value: 1
					}],
					dataKey: "value",
					nameKey: "label",
					innerRadius: 58,
					outerRadius: 82,
					paddingAngle: data.length > 1 ? 2 : 0,
					stroke: panel,
					strokeWidth: 2,
					startAngle: 90,
					endAngle: -270,
					isAnimationActive: true,
					children: (data.length ? data : [{ key: "empty" }]).map((s) => /* @__PURE__ */ jsx(Cell, { fill: data.length ? colors[s.key] ?? cssVar("--color-c3") : cssVar("--color-sunken") }, s.key))
				}), data.length > 0 && /* @__PURE__ */ jsx(Tooltip, { content: /* @__PURE__ */ jsx(TooltipBox, {}) })] })
			}), /* @__PURE__ */ jsxs("div", {
				className: "pointer-events-none absolute inset-0 flex flex-col items-center justify-center",
				children: [/* @__PURE__ */ jsx("span", {
					className: "text-title font-semibold tabular-nums text-c1",
					children: total
				}), /* @__PURE__ */ jsx("span", {
					className: "text-xs text-c3",
					children: "analysed"
				})]
			})]
		}), /* @__PURE__ */ jsx("ul", {
			className: "w-full space-y-1.5",
			children: slices.map((s) => /* @__PURE__ */ jsxs("li", {
				className: "flex items-center justify-between gap-3 text-sm",
				children: [/* @__PURE__ */ jsxs("span", {
					className: "flex items-center gap-2",
					children: [/* @__PURE__ */ jsx("span", {
						className: "h-2.5 w-2.5 rounded-[3px]",
						style: { background: colors[s.key] },
						"aria-hidden": true
					}), /* @__PURE__ */ jsx("span", {
						className: "text-c2",
						children: s.label
					})]
				}), /* @__PURE__ */ jsx("span", {
					className: "tabular-nums font-medium text-c1",
					children: s.value
				})]
			}, s.key))
		})]
	});
}
/** Counts per file family — one measure, one hue (brand), horizontal bars. */
function FamilyBars({ data }) {
	if (!data.length) return /* @__PURE__ */ jsx("p", {
		className: "text-sm text-c2",
		children: "No samples yet."
	});
	const brand = brandColor();
	const axis = cssVar("--color-c3");
	return /* @__PURE__ */ jsx(ResponsiveContainer, {
		width: "100%",
		height: Math.max(120, data.length * 34),
		children: /* @__PURE__ */ jsxs(BarChart, {
			data,
			layout: "vertical",
			margin: {
				top: 4,
				right: 16,
				bottom: 4,
				left: 8
			},
			children: [
				/* @__PURE__ */ jsx(XAxis, {
					type: "number",
					hide: true,
					allowDecimals: false
				}),
				/* @__PURE__ */ jsx(YAxis, {
					type: "category",
					dataKey: "label",
					width: 104,
					tickLine: false,
					axisLine: false,
					tick: {
						fill: axis,
						fontSize: 12
					}
				}),
				/* @__PURE__ */ jsx(Tooltip, {
					cursor: { fill: cssVar("--color-raised") },
					content: /* @__PURE__ */ jsx(TooltipBox, {})
				}),
				/* @__PURE__ */ jsx(Bar, {
					dataKey: "count",
					fill: brand,
					radius: [
						0,
						4,
						4,
						0
					],
					maxBarSize: 22,
					isAnimationActive: true
				})
			]
		})
	});
}
//#endregion
//#region src/pages/Dashboard.tsx
/**
* The dashboard buckets by the engine's verdict, not by the score band. The
* band legend it replaces filed every sample under 30 as "Low / clean" — which
* put five samples the engine had called malicious under a row captioned clean.
*
* `unclassified` is not a synonym for clean: it is a job the verdict engine
* never saw (analysed before it shipped, or a summary payload that omits it).
* Naming it is the honest alternative to guessing a verdict from the score.
*/
var VERDICT_BUCKETS = [
	{
		key: "malicious",
		label: "Malicious"
	},
	{
		key: "suspicious",
		label: "Suspicious"
	},
	{
		key: "clean",
		label: "Clean"
	},
	{
		key: "unclassified",
		label: "Not classified"
	}
];
var TONE_TEXT = {
	danger: "text-danger",
	warning: "text-warning",
	success: "text-success",
	brand: "text-brand-fg",
	neutral: "text-c1"
};
function StatTile({ label, value, tone = "neutral", caption, i = 0 }) {
	const v = useCountUp(value);
	return /* @__PURE__ */ jsxs("div", {
		className: "rise-in lift rounded-panel border border-hair bg-panel px-4 py-3.5",
		style: { "--i": i },
		children: [
			/* @__PURE__ */ jsx("div", {
				className: "label text-c3",
				children: label
			}),
			/* @__PURE__ */ jsx("div", {
				className: cx("mt-1 text-display font-semibold tabular-nums", TONE_TEXT[tone]),
				children: Math.round(v)
			}),
			caption && /* @__PURE__ */ jsx("div", {
				className: "text-xs mt-1 text-c3",
				children: caption
			})
		]
	});
}
function Dashboard() {
	const navigate = useNavigate();
	const { data, error, stale, refresh } = usePoll(() => api.get("/api/jobs/stats"), 4e3);
	if (!data) return /* @__PURE__ */ jsxs("div", {
		className: "space-y-6",
		children: [/* @__PURE__ */ jsx(PageHeader, { title: "Overview" }), /* @__PURE__ */ jsx(LoadState, {
			error,
			label: "Loading the dashboard",
			onRetry: refresh
		})]
	});
	const running = data.in_flight;
	const bucketCount = (k) => data.verdicts[k] ?? 0;
	const total = data.completed;
	const attention = data.needs_attention;
	const avg = data.average_score;
	const slices = VERDICT_BUCKETS.map((b) => ({
		key: b.key,
		label: b.label,
		value: bucketCount(b.key)
	}));
	const families = data.families.slice(0, 6).map((f) => ({
		label: familyLabel(f.family),
		count: f.count
	}));
	const topRisk = data.top_risk;
	return /* @__PURE__ */ jsxs("div", {
		className: "space-y-6",
		children: [
			/* @__PURE__ */ jsx("div", {
				className: "hero-glow",
				children: /* @__PURE__ */ jsx(PageHeader, {
					title: "Overview",
					lede: "A live picture of everything this deployment has analysed.",
					actions: /* @__PURE__ */ jsxs(Button, {
						variant: "primary",
						onClick: () => navigate("/submit"),
						children: [/* @__PURE__ */ jsx(Plus, {
							size: 16,
							"aria-hidden": true
						}), " New analysis"]
					})
				})
			}),
			stale && /* @__PURE__ */ jsx(StaleNotice, {
				error,
				onRetry: refresh
			}),
			/* @__PURE__ */ jsxs("div", {
				className: "grid grid-cols-2 gap-4 lg:grid-cols-4",
				children: [
					/* @__PURE__ */ jsx(StatTile, {
						label: "Analysed",
						value: total,
						caption: "completed jobs",
						i: 0
					}),
					/* @__PURE__ */ jsx(StatTile, {
						label: "Malicious",
						value: bucketCount("malicious"),
						tone: bucketCount("malicious") ? "danger" : "neutral",
						caption: "engine verdict",
						i: 1
					}),
					/* @__PURE__ */ jsx(StatTile, {
						label: "Needs attention",
						value: attention,
						tone: attention ? "warning" : "neutral",
						caption: "malicious or suspicious",
						i: 2
					}),
					/* @__PURE__ */ jsx(StatTile, {
						label: "Analysing now",
						value: running,
						tone: running ? "brand" : "neutral",
						caption: "in the queue",
						i: 3
					})
				]
			}),
			/* @__PURE__ */ jsxs("div", {
				className: "grid gap-6 lg:grid-cols-2",
				children: [/* @__PURE__ */ jsx(Panel, {
					title: "Verdict distribution",
					subtitle: `Average score ${avg.toFixed(0)} across ${total} sample${total === 1 ? "" : "s"}`,
					className: "rise-in",
					children: /* @__PURE__ */ jsx(VerdictDonut, {
						slices,
						total
					})
				}), /* @__PURE__ */ jsx(Panel, {
					title: "By file type",
					subtitle: "What is being submitted",
					className: "rise-in",
					children: /* @__PURE__ */ jsx(FamilyBars, { data: families })
				})]
			}),
			/* @__PURE__ */ jsx(Panel, {
				title: "Needs attention",
				subtitle: "Everything the engine flagged, worst verdict first",
				className: "rise-in",
				actions: /* @__PURE__ */ jsxs(Link, {
					to: "/queue",
					className: "text-sm inline-flex items-center gap-1 text-brand-fg hover:underline",
					children: ["Full queue ", /* @__PURE__ */ jsx(ArrowRight, {
						size: 14,
						"aria-hidden": true
					})]
				}),
				children: topRisk.length === 0 ? /* @__PURE__ */ jsx(Empty, {
					icon: /* @__PURE__ */ jsx(ShieldCheck, {
						size: 20,
						"aria-hidden": true
					}),
					children: "Nothing flagged yet. Submit a sample to see it here."
				}) : /* @__PURE__ */ jsx("div", {
					className: "divide-hair -my-2",
					children: topRisk.map((j) => /* @__PURE__ */ jsxs(Link, {
						to: `/job/${j.public_id}`,
						className: "flex items-center justify-between gap-3 py-2.5 transition-colors hover:bg-raised",
						children: [/* @__PURE__ */ jsxs("div", {
							className: "min-w-0",
							children: [/* @__PURE__ */ jsx("p", {
								className: "truncate text-body font-medium text-c1",
								children: j.original_name || "sample"
							}), /* @__PURE__ */ jsxs("p", {
								className: "text-xs text-c3",
								children: [
									familyLabel(j.family),
									" · ",
									timeAgo(j.created_at)
								]
							})]
						}), /* @__PURE__ */ jsxs("div", {
							className: "flex shrink-0 items-center gap-3",
							children: [/* @__PURE__ */ jsx(RiskMeter, { score: j.final_score }), /* @__PURE__ */ jsx(Status, { value: verdictOf(j) ?? j.risk_level })]
						})]
					}, j.public_id))
				})
			}),
			/* @__PURE__ */ jsxs("p", {
				className: cx("flex items-center justify-center gap-1.5 text-xs", stale ? "text-warning" : "text-c3"),
				children: [/* @__PURE__ */ jsx(Activity, {
					size: 12,
					"aria-hidden": true
				}), stale ? "Not live — the last update did not reach the API" : "Live — updates every few seconds"]
			})
		]
	});
}
//#endregion
//#region src/pages/Queue.tsx
var TERMINAL = /* @__PURE__ */ new Set([
	"completed",
	"failed",
	"awaiting_password"
]);
/**
* The API's own ceiling is 200; fifty is a screenful. The point of the pager is
* not the page size — it is that the rows past the first page are reachable at
* all. They were not: this page sent no parameters, took the default 50, and
* said "Every sample submitted to this deployment" over the top of them.
*/
var PAGE = 50;
function Queue() {
	const navigate = useNavigate();
	const [offset, setOffset] = useState(0);
	const { data, error, stale, refresh } = usePoll(() => api.get(`/api/jobs?limit=${PAGE}&offset=${offset}`), 3e3, [offset]);
	const jobs = data?.items ?? [];
	const total = data?.total ?? 0;
	const shownFrom = total === 0 ? 0 : offset + 1;
	const shownTo = offset + jobs.length;
	const pagedPastTheEnd = total > 0 && jobs.length === 0 && offset > 0;
	/**
	* Whole-row click, without the row *being* the control.
	*
	* A `<tr onClick>` is invisible to the keyboard and to assistive technology —
	* no role, no tab stop, no Enter handling — which left every report in this
	* product unreachable without a mouse (WCAG 2.1.1 and 4.1.2, both Level A).
	* The real control is the link in the first cell; this handler only widens its
	* hit area for pointer users, and stands down when the pointer was already on
	* the link so the click is not handled twice.
	*/
	const rowClick = (e, publicId) => {
		if (e.target.closest("a")) return;
		navigate(`/job/${publicId}`);
	};
	return /* @__PURE__ */ jsxs("div", {
		className: "space-y-6",
		children: [
			/* @__PURE__ */ jsx(PageHeader, {
				title: "Analysis queue",
				lede: "Every sample submitted to this deployment, newest first."
			}),
			stale && /* @__PURE__ */ jsx(StaleNotice, {
				error,
				onRetry: refresh
			}),
			/* @__PURE__ */ jsx(Panel, {
				padded: false,
				className: "overflow-hidden",
				children: !data ? /* @__PURE__ */ jsx("div", {
					className: "p-5",
					children: /* @__PURE__ */ jsx(LoadState, {
						error,
						label: "Loading the queue",
						onRetry: refresh
					})
				}) : pagedPastTheEnd ? /* @__PURE__ */ jsxs("div", {
					className: "p-5 space-y-3",
					children: [/* @__PURE__ */ jsxs(Empty, {
						icon: /* @__PURE__ */ jsx(FileSearch, {
							size: 20,
							"aria-hidden": true
						}),
						children: [
							"Nothing on this page — the queue holds ",
							total,
							" sample",
							total === 1 ? "" : "s",
							"."
						]
					}), /* @__PURE__ */ jsx("div", {
						className: "flex justify-center",
						children: /* @__PURE__ */ jsx(Button, {
							size: "sm",
							onClick: () => setOffset(0),
							children: "Back to the newest"
						})
					})]
				}) : jobs.length === 0 ? /* @__PURE__ */ jsx("div", {
					className: "p-5",
					children: /* @__PURE__ */ jsx(Empty, {
						icon: /* @__PURE__ */ jsx(FileSearch, {
							size: 20,
							"aria-hidden": true
						}),
						children: "Nothing analysed yet. Submit a file or URL to get started."
					})
				}) : /* @__PURE__ */ jsxs("div", {
					className: "p-5",
					children: [/* @__PURE__ */ jsxs(Table, {
						minWidth: 720,
						children: [/* @__PURE__ */ jsx("thead", { children: /* @__PURE__ */ jsxs("tr", { children: [
							/* @__PURE__ */ jsx(TH, { children: "Sample" }),
							/* @__PURE__ */ jsx(TH, { children: "Type" }),
							/* @__PURE__ */ jsx(TH, { children: "Source" }),
							/* @__PURE__ */ jsx(TH, { children: "Risk" }),
							/* @__PURE__ */ jsx(TH, { children: "Status" }),
							/* @__PURE__ */ jsx(TH, {
								numeric: true,
								children: "Submitted"
							})
						] }) }), /* @__PURE__ */ jsx("tbody", { children: jobs.map((job) => /* @__PURE__ */ jsxs("tr", {
							onClick: (e) => rowClick(e, job.public_id),
							className: "cursor-pointer transition-colors hover:bg-raised",
							children: [
								/* @__PURE__ */ jsx(TD, { children: /* @__PURE__ */ jsxs("div", {
									className: "min-w-0",
									children: [/* @__PURE__ */ jsxs(Link, {
										to: `/job/${job.public_id}`,
										className: "block truncate font-medium text-c1 hover:underline",
										children: [job.original_name || "sample", /* @__PURE__ */ jsx("span", {
											className: "sr-only",
											children: " — open analysis report"
										})]
									}), /* @__PURE__ */ jsxs("div", {
										className: "tech text-c3",
										children: [job.sha256.slice(0, 24), "…"]
									})]
								}) }),
								/* @__PURE__ */ jsx(TD, {
									muted: true,
									children: familyLabel(job.family)
								}),
								/* @__PURE__ */ jsx(TD, {
									muted: true,
									children: job.source === "url" ? "URL" : "Upload"
								}),
								/* @__PURE__ */ jsx(TD, { children: TERMINAL.has(job.status) && job.status === "completed" ? /* @__PURE__ */ jsxs("span", {
									className: "flex flex-wrap items-center gap-2",
									children: [/* @__PURE__ */ jsx(RiskMeter, { score: job.final_score }), verdictOf(job) && /* @__PURE__ */ jsx(Status, { value: verdictOf(job) })]
								}) : /* @__PURE__ */ jsx("span", {
									className: "text-sm text-c3",
									children: "—"
								}) }),
								/* @__PURE__ */ jsx(TD, { children: /* @__PURE__ */ jsx(Status, { value: job.status }) }),
								/* @__PURE__ */ jsx(TD, {
									numeric: true,
									muted: true,
									children: timeAgo(job.created_at)
								})
							]
						}, job.public_id)) })]
					}), /* @__PURE__ */ jsxs("div", {
						className: "mt-4 flex flex-wrap items-center justify-between gap-3",
						children: [/* @__PURE__ */ jsxs("p", {
							className: "text-sm text-c3 tabular-nums",
							children: [
								"Showing ",
								shownFrom,
								"–",
								shownTo,
								" of ",
								total
							]
						}), total > PAGE && /* @__PURE__ */ jsxs("div", {
							className: "flex items-center gap-2",
							children: [/* @__PURE__ */ jsx(Button, {
								size: "sm",
								variant: "ghost",
								disabled: offset === 0,
								onClick: () => setOffset(Math.max(0, offset - PAGE)),
								children: "Newer"
							}), /* @__PURE__ */ jsx(Button, {
								size: "sm",
								variant: "ghost",
								disabled: shownTo >= total,
								onClick: () => setOffset(offset + PAGE),
								children: "Older"
							})]
						})]
					})]
				})
			})
		]
	});
}
//#endregion
//#region src/pages/Integrations.tsx
var KIND_LABEL = {
	native: "Native engine",
	emulator: "Emulator",
	"opensource-sandbox": "Open-source sandbox",
	"threat-intel": "Threat intelligence"
};
function EngineCard({ e, i = 0 }) {
	return /* @__PURE__ */ jsxs("div", {
		className: "rise-in lift rounded-control border border-hair bg-panel p-4",
		style: { "--i": i },
		children: [
			/* @__PURE__ */ jsxs("div", {
				className: "flex items-start justify-between gap-2",
				children: [/* @__PURE__ */ jsxs("div", {
					className: "min-w-0",
					children: [/* @__PURE__ */ jsx("p", {
						className: "text-body font-medium text-c1",
						children: e.name
					}), e.vendor && /* @__PURE__ */ jsx("p", {
						className: "text-xs text-c3",
						children: e.vendor
					})]
				}), e.configured ? /* @__PURE__ */ jsxs("span", {
					className: "inline-flex items-center gap-1 text-xs font-medium text-success",
					children: [/* @__PURE__ */ jsx(CheckCircle2, {
						size: 14,
						"aria-hidden": true
					}), " Enabled"]
				}) : /* @__PURE__ */ jsxs("span", {
					className: "inline-flex items-center gap-1 text-xs text-c3",
					children: [/* @__PURE__ */ jsx(Circle, {
						size: 14,
						"aria-hidden": true
					}), " Available"]
				})]
			}),
			/* @__PURE__ */ jsxs("div", {
				className: "mt-2 flex flex-wrap gap-1.5",
				children: [/* @__PURE__ */ jsx(Chip, {
					tone: "neutral",
					children: KIND_LABEL[e.kind] ?? e.kind
				}), /* @__PURE__ */ jsx(Chip, {
					tone: e.tier === "dynamic" ? "brand" : "info",
					children: e.tier
				})]
			}),
			e.notes && /* @__PURE__ */ jsx("p", {
				className: "text-sm mt-2 text-c2",
				children: e.notes
			}),
			e.requires && !e.configured && /* @__PURE__ */ jsxs("p", {
				className: "text-xs mt-2 text-c3",
				children: ["Enable: ", e.requires]
			})
		]
	});
}
function Integrations() {
	const { data: caps, error, stale, refresh } = usePoll(() => api.get("/api/capabilities"), 1e4);
	if (!caps) return /* @__PURE__ */ jsxs("div", {
		className: "space-y-6",
		children: [/* @__PURE__ */ jsx(PageHeader, { title: "Integrations and capabilities" }), /* @__PURE__ */ jsx(LoadState, {
			error,
			label: "Loading capabilities",
			onRetry: refresh
		})]
	});
	const configured = caps.integrations.filter((e) => e.configured).length;
	const dynamic = caps.integrations.filter((e) => e.tier === "dynamic");
	const staticIntel = caps.integrations.filter((e) => e.tier === "static");
	return /* @__PURE__ */ jsxs("div", {
		className: "space-y-6",
		children: [
			/* @__PURE__ */ jsx(PageHeader, {
				title: "Integrations and capabilities",
				lede: "What this deployment can honestly do. Static analysis runs here; dynamic engines run on the operator's isolated worker."
			}),
			stale && /* @__PURE__ */ jsx(StaleNotice, {
				error,
				onRetry: refresh
			}),
			/* @__PURE__ */ jsxs("div", {
				className: "grid grid-cols-2 gap-4 sm:grid-cols-4",
				children: [
					/* @__PURE__ */ jsx(Metric, {
						label: "Static analyzers",
						value: caps.static_analyzers.length,
						size: "sm"
					}),
					/* @__PURE__ */ jsx(Metric, {
						label: "YARA rules",
						value: caps.yara.loaded,
						size: "sm"
					}),
					/* @__PURE__ */ jsx(Metric, {
						label: "Engines",
						value: caps.integrations.length,
						size: "sm"
					}),
					/* @__PURE__ */ jsx(Metric, {
						label: "Enabled now",
						value: configured,
						size: "sm",
						tone: configured >= 4 ? "success" : "warning"
					})
				]
			}),
			/* @__PURE__ */ jsxs(Panel, {
				title: "Data sovereignty",
				subtitle: "Where analysis data may go, and what has been refused",
				children: [
					/* @__PURE__ */ jsxs("div", {
						className: "flex items-start gap-3",
						children: [caps.sovereignty?.enabled ? /* @__PURE__ */ jsx(ShieldCheck, {
							size: 18,
							className: "mt-0.5 shrink-0 text-success",
							"aria-hidden": true
						}) : /* @__PURE__ */ jsx(ShieldAlert, {
							size: 18,
							className: "mt-0.5 shrink-0 text-warning",
							"aria-hidden": true
						}), /* @__PURE__ */ jsxs("div", {
							className: "min-w-0",
							children: [/* @__PURE__ */ jsx("p", {
								className: "text-body text-c1",
								children: caps.sovereignty?.statement ?? "Sovereignty posture not reported by this build."
							}), caps.sovereignty && /* @__PURE__ */ jsxs("p", {
								className: "text-sm mt-1 text-c2",
								children: [
									caps.sovereignty.outbound_refusals?.total ?? 0,
									" outbound call",
									caps.sovereignty.outbound_refusals?.total === 1 ? "" : "s",
									" refused ·",
									" ",
									caps.sovereignty.destinations?.filter((d) => !d.allowed).length ?? 0,
									" of",
									" ",
									caps.sovereignty.destinations?.length ?? 0,
									" destinations closed"
								]
							})]
						})]
					}),
					caps.sovereignty?.destinations?.length ? /* @__PURE__ */ jsx("div", {
						className: "divide-hair mt-4",
						children: caps.sovereignty.destinations.map((d) => /* @__PURE__ */ jsxs("div", {
							className: "flex items-start justify-between gap-3 py-2",
							children: [/* @__PURE__ */ jsx("p", {
								className: "min-w-0 text-sm text-c2",
								children: d.what_would_leave
							}), /* @__PURE__ */ jsx(Chip, {
								tone: d.allowed ? d.is_deliberate_exception ? "info" : "warning" : "success",
								children: d.allowed ? d.is_deliberate_exception ? "Allowed by design" : "Open" : "Blocked"
							})]
						}, d.key))
					}) : null,
					caps.retention && /* @__PURE__ */ jsx("p", {
						className: "text-sm mt-4 border-t border-hair pt-3 text-c2",
						children: caps.retention.statement
					})
				]
			}),
			/* @__PURE__ */ jsx(Panel, {
				title: "Dynamic engines",
				subtitle: "Detonation and behaviour — run off-host on an isolated worker",
				children: /* @__PURE__ */ jsx("div", {
					className: "grid gap-3 sm:grid-cols-2 lg:grid-cols-3",
					children: dynamic.map((e, i) => /* @__PURE__ */ jsx(EngineCard, {
						e,
						i
					}, e.key))
				})
			}),
			/* @__PURE__ */ jsx(Panel, {
				title: "Static and intelligence engines",
				subtitle: "Safe to run in-process — no sample is executed",
				children: /* @__PURE__ */ jsx("div", {
					className: "grid gap-3 sm:grid-cols-2 lg:grid-cols-3",
					children: staticIntel.map((e, i) => /* @__PURE__ */ jsx(EngineCard, {
						e,
						i
					}, e.key))
				})
			}),
			/* @__PURE__ */ jsxs("div", {
				className: "grid gap-6 lg:grid-cols-2",
				children: [/* @__PURE__ */ jsxs(Panel, {
					title: "Static analyzers",
					subtitle: "Per-family parsers, dispatched by content type",
					children: [/* @__PURE__ */ jsx("div", {
						className: "flex flex-wrap gap-1.5",
						children: caps.static_analyzers.map((a) => /* @__PURE__ */ jsx(Chip, {
							tone: "neutral",
							children: a
						}, a))
					}), Object.keys(caps.unavailable_analyzers || {}).length > 0 && /* @__PURE__ */ jsxs("p", {
						className: "text-xs mt-3 text-warning",
						children: ["Unavailable: ", Object.keys(caps.unavailable_analyzers).join(", ")]
					})]
				}), /* @__PURE__ */ jsx(Panel, {
					title: "Scoring model",
					children: /* @__PURE__ */ jsxs("div", {
						className: "flex items-start gap-3",
						children: [/* @__PURE__ */ jsx(Cpu, {
							size: 18,
							className: "mt-0.5 shrink-0 text-brand-fg",
							"aria-hidden": true
						}), /* @__PURE__ */ jsxs("div", { children: [
							/* @__PURE__ */ jsx("p", {
								className: "text-body text-c1",
								children: caps.scoring.model
							}),
							/* @__PURE__ */ jsxs("p", {
								className: "text-sm mt-1 text-c2",
								children: [
									"Aggregation split: rule ",
									caps.scoring.weights.rule,
									" · model ",
									caps.scoring.weights.model,
									". Tunable under Tuning."
								]
							}),
							/* @__PURE__ */ jsxs("p", {
								className: "text-xs mt-2 text-c3",
								children: ["AI provider: ", caps.ai_provider]
							})
						] })]
					})
				})]
			})
		]
	});
}
//#endregion
//#region __probe__/stubCaps.ts
function useCapabilities() {
	return globalThis.__CAPS__ ?? null;
}
//#endregion
//#region src/pages/Submit.tsx
function Submit() {
	const navigate = useNavigate();
	const caps = useCapabilities();
	const [mode, setMode] = useState("file");
	const [file, setFile] = useState(null);
	const [password, setPassword] = useState("");
	const [url, setUrl] = useState("");
	const [dragging, setDragging] = useState(false);
	const [busy, setBusy] = useState(false);
	const [error, setError] = useState(null);
	const inputRef = useRef(null);
	const maxMb = caps?.max_sample_mb ?? 32;
	function onDrop(e) {
		e.preventDefault();
		setDragging(false);
		const dropped = e.dataTransfer.files?.[0];
		if (dropped) setFile(dropped);
	}
	async function submitFile(e) {
		e.preventDefault();
		if (!file) return;
		setBusy(true);
		setError(null);
		try {
			const form = new FormData();
			form.append("file", file);
			if (password) form.append("password", password);
			const job = await api.upload("/api/analyze", form);
			navigate(`/job/${job.public_id}`);
		} catch (err) {
			setError(err instanceof Error ? err.message : "Submission failed");
		} finally {
			setBusy(false);
		}
	}
	async function submitUrl(e) {
		e.preventDefault();
		if (!url.trim()) return;
		setBusy(true);
		setError(null);
		try {
			const job = await api.post("/api/analyze/url", { url: url.trim() });
			navigate(`/job/${job.public_id}`);
		} catch (err) {
			setError(err instanceof Error ? err.message : "Submission failed");
		} finally {
			setBusy(false);
		}
	}
	return /* @__PURE__ */ jsxs("div", {
		className: "space-y-6",
		children: [/* @__PURE__ */ jsx("div", {
			className: "hero-glow",
			children: /* @__PURE__ */ jsx(PageHeader, {
				title: "Submit a sample",
				lede: "Upload a file or paste a URL. The sample is quarantined and analysed statically — it is never executed on this server."
			})
		}), /* @__PURE__ */ jsxs("div", {
			className: "grid gap-6 lg:grid-cols-[1.6fr_1fr]",
			children: [/* @__PURE__ */ jsxs(Panel, {
				tone: "feature",
				className: "rise-in",
				children: [/* @__PURE__ */ jsx("div", {
					className: "mb-4",
					children: /* @__PURE__ */ jsx(Tabs, {
						label: "Submission type",
						value: mode,
						onChange: setMode,
						tabs: [{
							key: "file",
							label: "File"
						}, {
							key: "url",
							label: "URL"
						}]
					})
				}), mode === "file" ? /* @__PURE__ */ jsxs("form", {
					onSubmit: submitFile,
					className: "space-y-4",
					children: [
						/* @__PURE__ */ jsxs("div", {
							onDragOver: (e) => {
								e.preventDefault();
								setDragging(true);
							},
							onDragLeave: () => setDragging(false),
							onDrop,
							onClick: () => inputRef.current?.click(),
							role: "button",
							tabIndex: 0,
							onKeyDown: (e) => {
								if (e.key === "Enter" || e.key === " ") inputRef.current?.click();
							},
							className: "flex cursor-pointer flex-col items-center justify-center gap-3 rounded-panel border-2 border-dashed px-6 py-12 text-center transition-colors " + (dragging ? "border-brand bg-brand/8" : "border-line bg-raised hover:border-line-strong"),
							children: [
								/* @__PURE__ */ jsx(FileUp, {
									size: 28,
									className: "text-c3",
									"aria-hidden": true
								}),
								file ? /* @__PURE__ */ jsxs("div", { children: [/* @__PURE__ */ jsx("p", {
									className: "text-body font-medium text-c1",
									children: file.name
								}), /* @__PURE__ */ jsx("p", {
									className: "text-xs mt-0.5 text-c3",
									children: formatBytes(file.size)
								})] }) : /* @__PURE__ */ jsxs("div", { children: [/* @__PURE__ */ jsx("p", {
									className: "text-body text-c1",
									children: "Drop a file here, or click to choose"
								}), /* @__PURE__ */ jsxs("p", {
									className: "text-xs mt-1 text-c3",
									children: [
										"Up to ",
										maxMb,
										" MB"
									]
								})] }),
								/* @__PURE__ */ jsx("input", {
									ref: inputRef,
									type: "file",
									className: "hidden",
									onChange: (e) => setFile(e.target.files?.[0] ?? null)
								})
							]
						}),
						/* @__PURE__ */ jsx(Input, {
							label: "Archive password (optional)",
							type: "password",
							value: password,
							onChange: (e) => setPassword(e.target.value),
							placeholder: "Only for encrypted .zip / .rar / .7z",
							hint: "If the archive is encrypted and you leave this blank, the job pauses and asks for it — the engine never guesses a password."
						}),
						error && /* @__PURE__ */ jsx(Callout, {
							tone: "danger",
							title: "Submission failed",
							children: error
						}),
						/* @__PURE__ */ jsxs(Button, {
							type: "submit",
							variant: "primary",
							size: "lg",
							busy,
							disabled: !file,
							className: "w-full",
							children: [/* @__PURE__ */ jsx(FileUp, {
								size: 16,
								"aria-hidden": true
							}), "Analyse file"]
						})
					]
				}) : /* @__PURE__ */ jsxs("form", {
					onSubmit: submitUrl,
					className: "space-y-4",
					children: [
						/* @__PURE__ */ jsx(Input, {
							label: "URL",
							type: "url",
							value: url,
							onChange: (e) => setUrl(e.target.value),
							placeholder: "https://example.com/suspicious.bin",
							hint: "The server downloads it. Requests to private, loopback and cloud-metadata addresses are refused.",
							autoFocus: true
						}),
						error && /* @__PURE__ */ jsx(Callout, {
							tone: "danger",
							title: "Submission failed",
							children: error
						}),
						/* @__PURE__ */ jsxs(Button, {
							type: "submit",
							variant: "primary",
							size: "lg",
							busy,
							disabled: !url.trim(),
							className: "w-full",
							children: [/* @__PURE__ */ jsx(Link2, {
								size: 16,
								"aria-hidden": true
							}), "Fetch and analyse"]
						})
					]
				})]
			}), /* @__PURE__ */ jsxs("div", {
				className: "space-y-4",
				children: [/* @__PURE__ */ jsx(Panel, {
					title: "How it is handled",
					tone: "quiet",
					padded: true,
					children: /* @__PURE__ */ jsxs("ul", {
						className: "space-y-3 text-sm text-c2",
						children: [
							/* @__PURE__ */ jsxs("li", {
								className: "flex gap-2.5",
								children: [/* @__PURE__ */ jsx(ShieldAlert, {
									size: 16,
									className: "mt-0.5 shrink-0 text-brand-fg",
									"aria-hidden": true
								}), /* @__PURE__ */ jsx("span", { children: "Stored under its content hash, owner-read-only, never marked executable." })]
							}),
							/* @__PURE__ */ jsxs("li", {
								className: "flex gap-2.5",
								children: [/* @__PURE__ */ jsx(Lock, {
									size: 16,
									className: "mt-0.5 shrink-0 text-brand-fg",
									"aria-hidden": true
								}), /* @__PURE__ */ jsx("span", { children: "Static analysis only here: parsers and YARA. Detonation runs off-host on an isolated worker." })]
							}),
							/* @__PURE__ */ jsxs("li", {
								className: "flex gap-2.5",
								children: [/* @__PURE__ */ jsx(FileUp, {
									size: 16,
									className: "mt-0.5 shrink-0 text-brand-fg",
									"aria-hidden": true
								}), /* @__PURE__ */ jsx("span", { children: "You get a job id immediately and can watch each stage as it runs." })]
							})
						]
					})
				}), caps && /* @__PURE__ */ jsx(Panel, {
					title: "Supported types",
					tone: "quiet",
					padded: true,
					children: /* @__PURE__ */ jsx("div", {
						className: "flex flex-wrap gap-1.5",
						children: caps.supported_extensions.map((ext) => /* @__PURE__ */ jsx("span", {
							className: "tech rounded-chip border border-hair bg-raised px-1.5 py-0.5 text-c2",
							children: ext
						}, ext))
					})
				})]
			})]
		})]
	});
}
//#endregion
//#region __probe__/entry.tsx
var g = globalThis;
function set(payload, opts = {}) {
	g.__POLL__ = payload;
	g.__STALE__ = opts.stale ?? false;
	g.__ERR__ = opts.error ?? null;
}
function renderJob(job, opts = {}) {
	set(job, opts);
	return renderToString(/* @__PURE__ */ jsx(MemoryRouter, {
		initialEntries: ["/job/probe-id"],
		children: /* @__PURE__ */ jsx(Routes, { children: /* @__PURE__ */ jsx(Route, {
			path: "/job/:id",
			element: /* @__PURE__ */ jsx(JobDetail, {})
		}) })
	}));
}
function renderDashboard(stats, opts = {}) {
	set(stats, opts);
	return renderToString(/* @__PURE__ */ jsx(MemoryRouter, {
		initialEntries: ["/"],
		children: /* @__PURE__ */ jsx(Routes, { children: /* @__PURE__ */ jsx(Route, {
			path: "/",
			element: /* @__PURE__ */ jsx(Dashboard, {})
		}) })
	}));
}
function renderQueue(page, opts = {}) {
	set(page, opts);
	return renderToString(/* @__PURE__ */ jsx(MemoryRouter, {
		initialEntries: ["/queue"],
		children: /* @__PURE__ */ jsx(Routes, { children: /* @__PURE__ */ jsx(Route, {
			path: "/queue",
			element: /* @__PURE__ */ jsx(Queue, {})
		}) })
	}));
}
function renderIntegrations(caps, opts = {}) {
	set(caps, opts);
	return renderToString(/* @__PURE__ */ jsx(MemoryRouter, {
		initialEntries: ["/integrations"],
		children: /* @__PURE__ */ jsx(Routes, { children: /* @__PURE__ */ jsx(Route, {
			path: "/integrations",
			element: /* @__PURE__ */ jsx(Integrations, {})
		}) })
	}));
}
function renderSubmit(caps) {
	g.__CAPS__ = caps;
	return renderToString(/* @__PURE__ */ jsx(MemoryRouter, {
		initialEntries: ["/submit"],
		children: /* @__PURE__ */ jsx(Routes, { children: /* @__PURE__ */ jsx(Route, {
			path: "/submit",
			element: /* @__PURE__ */ jsx(Submit, {})
		}) })
	}));
}
//#endregion
export { renderDashboard, renderIntegrations, renderJob, renderQueue, renderSubmit };
