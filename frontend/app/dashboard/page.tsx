import { redirect } from "next/navigation";
import { fetchMe } from "../../services/api";
import LogoutButton from "../../components/LogoutButton";

export default async function DashboardPage() {
  try {
    await fetchMe();
  } catch {
    redirect("/login");
  }
  return (
    <main className="p-8">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-semibold text-slate-900">대시보드</h1>
          <p className="mt-2 text-slate-700">최근 이메일 분석 결과와 알림을 확인하세요.</p>
        </div>
        <LogoutButton />
      </div>
      <div className="mt-6 grid gap-4 md:grid-cols-2">
        <div className="rounded-lg bg-white p-4 shadow">최근 분석 결과 위젯 (구현 예정)</div>
        <div className="rounded-lg bg-white p-4 shadow">보안 알림 위젯 (구현 예정)</div>
      </div>
    </main>
  );
}
