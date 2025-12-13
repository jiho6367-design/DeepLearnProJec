export async function fetchEmails() {
  const res = await fetch(`${process.env.NEXT_PUBLIC_API_BASE_URL}/api/emails`, {
    credentials: "include",
    cache: "no-store",
  });
  if (!res.ok) {
    throw new Error("Failed to fetch emails");
  }
  return res.json();
}

export async function fetchEmail(messageId: string) {
  const res = await fetch(`${process.env.NEXT_PUBLIC_API_BASE_URL}/api/emails/${messageId}`, {
    credentials: "include",
    cache: "no-store",
  });
  if (!res.ok) {
    throw new Error("Failed to fetch email detail");
  }
  return res.json();
}

export async function fetchMe() {
  const res = await fetch(`${process.env.NEXT_PUBLIC_API_BASE_URL}/api/auth/me`, {
    credentials: "include",
    cache: "no-store",
  });
  if (!res.ok) {
    throw new Error("Unauthorized");
  }
  return res.json();
}
