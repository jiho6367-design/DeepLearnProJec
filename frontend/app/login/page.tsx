"use client";

import React from "react";
import { LoginButton } from "../../components/LoginButton";

export default function LoginPage() {
  return (
    <main className="flex min-h-screen items-center justify-center bg-slate-100">
      <div className="rounded-lg bg-white p-10 shadow-lg">
        <h1 className="mb-4 text-2xl font-semibold text-slate-900">PhishGuard에 로그인</h1>
        <p className="mb-6 text-sm text-slate-600">Google 계정으로 안전하게 로그인하고 메일을 검사하세요.</p>
        <LoginButton />
      </div>
    </main>
  );
}
