import { redirect } from "next/navigation";
import { fetchMe } from "../../services/api";

export default async function HistoryPage() {
  try {
    await fetchMe();
  } catch {
    redirect("/login");
  }
  return (
    <main className="p-8">
      <h1 className="text-xl font-semibold text-slate-900">분석 기록</h1>
      <p className="text-slate-700">최근 분석 결과와 피드백을 이 영역에서 렌더링합니다.</p>
    </main>
  );
}
