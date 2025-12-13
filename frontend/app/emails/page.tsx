import { redirect } from "next/navigation";
import EmailsClient from "./EmailsClient";
import { fetchMe } from "../../services/api";

export default async function EmailsPage() {
  try {
    await fetchMe();
  } catch {
    redirect("/login");
  }
  return (
    <main className="p-8">
      <h1 className="text-xl font-semibold text-slate-900">이메일</h1>
      <p className="text-slate-700">Gmail에서 최근 메시지를 불러옵니다.</p>
      <EmailsClient />
    </main>
  );
}
