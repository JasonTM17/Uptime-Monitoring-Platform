import { useMutation, useQueryClient } from "@tanstack/react-query";
import { useNavigate } from "react-router-dom";
import { useSession } from "../auth/session";
import { createMonitor } from "./queries";
import { MonitorForm, type MonitorFormValues } from "./MonitorForm";

export function MonitorsPage() {
  const { user } = useSession();
  const qc = useQueryClient();
  const navigate = useNavigate();

  const create = useMutation({ mutationFn: createMonitor });

  const submit = async (v: MonitorFormValues) => {
    const res = await create.mutateAsync({
      name: v.name.trim(),
      target_url: v.target_url.trim(),
      interval_seconds: v.interval_seconds,
      timeout_seconds: v.timeout_seconds,
      ...(v.expected_status !== null
        ? { expected_status: v.expected_status }
        : {}),
    });
    await qc.invalidateQueries({ queryKey: ["monitors", user?.id] });
    await qc.invalidateQueries({ queryKey: ["dashboard-summary", user?.id] });
    if (res.data) navigate(`/monitors/${res.data.id}`);
  };

  return (
    <div className="flex flex-col gap-4">
      <h1 className="text-lg font-semibold">New monitor</h1>
      <MonitorForm
        initial={{
          name: "",
          target_url: "",
          interval_seconds: 300,
          timeout_seconds: 5,
          expected_status: 200,
        }}
        onSubmit={submit}
        submitLabel="Create monitor"
        generationConflict={false}
        onDismissConflict={() => {}}
      />
    </div>
  );
}
