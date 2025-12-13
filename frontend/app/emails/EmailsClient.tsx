"use client";

import React, { useEffect, useState } from "react";
import { fetchEmails } from "../../services/api";

type EmailItem = { id: string; subject?: string; from?: string; date?: string; snippet?: string };
type AnalysisResult = {
  verdict: string;
  score: number;
  summary: string;
  reasons?: string[];
  recommended_actions?: string[];
};

export default function EmailsClient() {
  const [emails, setEmails] = useState<EmailItem[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [selected, setSelected] = useState<string | null>(null);
  const [analysis, setAnalysis] = useState<AnalysisResult | null>(null);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    fetchEmails()
      .then((data) => setEmails(data.messages ?? []))
      .catch((err) => setError(err.message));
  }, []);

  const handleAnalyze = async (id: string, mode: "fast" | "deep" = "fast") => {
    setSelected(id);
    setLoading(true);
    setAnalysis(null);
    try {
      const res = await fetch(`${process.env.NEXT_PUBLIC_API_BASE_URL}/api/analyze`, {
        method: "POST",
        credentials: "include",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ message_id: id, mode }),
      });
      const data = await res.json();
      if (!res.ok) {
        throw new Error(data?.error?.message || "분석 실패");
      }
      setAnalysis(data);
    } catch (e: any) {
      setError(e.message);
    } finally {
      setLoading(false);
    }
  };

  if (error) {
    return <p className="text-red-600">이메일을 불러오지 못했습니다: {error}</p>;
  }

  return (
    <div className="mt-4 grid gap-3">
      {emails.map((mail) => (
        <div key={mail.id} className="rounded border border-slate-200 bg-white p-4 shadow-sm">
          <div className="text-sm text-slate-600">{mail.from}</div>
          <div className="text-lg font-semibold text-slate-900">{mail.subject || "(제목 없음)"}</div>
          <div className="text-xs text-slate-500">{mail.date}</div>
          <p className="mt-2 text-sm text-slate-700">{mail.snippet}</p>
          <div className="mt-3 flex gap-2">
            <button
              className="rounded bg-emerald-600 px-3 py-1 text-white hover:bg-emerald-500 disabled:opacity-60"
              disabled={loading && selected === mail.id}
              onClick={() => handleAnalyze(mail.id, "fast")}
            >
              {loading && selected === mail.id ? "분석 중..." : "분석하기"}
            </button>
            <button
              className="rounded border border-emerald-600 px-3 py-1 text-emerald-700 hover:bg-emerald-50 disabled:opacity-60"
              disabled={loading && selected === mail.id}
              onClick={() => handleAnalyze(mail.id, "deep")}
            >
              Deep 분석
            </button>
          </div>
          {analysis && selected === mail.id && (
            <div className="mt-3 rounded border border-slate-200 bg-slate-50 p-3">
              <div className="flex items-center justify-between">
                <span className="rounded-full bg-slate-800 px-2 py-1 text-xs text-white">{analysis.verdict}</span>
                <span className="text-sm text-slate-700">score: {analysis.score?.toFixed(2)}</span>
              </div>
              <p className="mt-2 text-sm text-slate-800">{analysis.summary}</p>
              {analysis.reasons?.length ? (
                <ul className="mt-2 list-disc pl-5 text-sm text-slate-700">
                  {analysis.reasons.map((r, idx) => (
                    <li key={idx}>{r}</li>
                  ))}
                </ul>
              ) : null}
              {analysis.recommended_actions?.length ? (
                <div className="mt-2">
                  <div className="text-xs font-semibold text-slate-700">Recommended actions</div>
                  <ul className="list-disc pl-5 text-sm text-slate-700">
                    {analysis.recommended_actions.map((r, idx) => (
                      <li key={idx}>{r}</li>
                    ))}
                  </ul>
                </div>
              ) : null}
            </div>
          )}
        </div>
      ))}
      {!emails.length && <p className="text-slate-600">표시할 이메일이 없습니다.</p>}
    </div>
  );
}
