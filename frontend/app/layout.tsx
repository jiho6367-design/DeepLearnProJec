import "./globals.css";
import React from "react";

export const metadata = {
  title: "PhishGuard",
  description: "Phishing detection SaaS",
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="ko">
      <body className="bg-slate-50 text-slate-900">{children}</body>
    </html>
  );
}
