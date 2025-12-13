"use client";

import React from "react";

const LogoutButton: React.FC = () => {
  const handleLogout = async () => {
    try {
      await fetch(`${process.env.NEXT_PUBLIC_API_BASE_URL}/api/auth/logout`, {
        method: "POST",
        credentials: "include",
      });
    } catch (e) {
      console.error(e);
    } finally {
      window.location.href = "/login";
    }
  };
  return (
    <button
      onClick={handleLogout}
      className="rounded bg-slate-800 px-4 py-2 text-white shadow hover:bg-slate-700"
    >
      Logout
    </button>
  );
};

export default LogoutButton;
