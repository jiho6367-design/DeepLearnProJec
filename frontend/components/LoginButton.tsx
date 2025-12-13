"use client";

import React, { useState } from "react";

export const LoginButton: React.FC = () => {
  const [loading, setLoading] = useState(false);
  const handleLogin = async () => {
    setLoading(true);
    try {
      const res = await fetch(`${process.env.NEXT_PUBLIC_API_BASE_URL}/api/auth/google/login`, {
        credentials: "include",
      });
      const data = await res.json();
      if (data?.auth_url) {
        window.location.href = data.auth_url;
      } else {
        alert("로그인 URL을 가져오지 못했습니다.");
      }
    } catch (err) {
      console.error(err);
      alert("로그인 요청 중 오류가 발생했습니다.");
    } finally {
      setLoading(false);
    }
  };
  return (
    <button
      onClick={handleLogin}
      className="rounded bg-blue-600 px-4 py-2 text-white shadow hover:bg-blue-500 disabled:opacity-60"
      disabled={loading}
    >
      {loading ? "연결 중..." : "Google로 로그인"}
    </button>
  );
};
