"use client";

export const LoginButton = () => {
  const handleLogin = () => {
    const base = process.env.NEXT_PUBLIC_API_BASE_URL;
    window.location.href = `${base}/api/auth/google/login`;
  };

  return (
    <button onClick={handleLogin}>
      Google로 로그인
    </button>
  );
};
