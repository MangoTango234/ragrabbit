import { redirect } from "next/navigation";

export default function LoginPage() {
  redirect("/dashboard/indexing");
  return null;
}
