import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import { SegmentedControl } from "./SegmentedControl";

const OPTS = [
  { value: "", label: "All" },
  { value: "a", label: "A" },
  { value: "b", label: "B" },
] as const;

describe("SegmentedControl", () => {
  it("exposes the group label and pressed state", () => {
    render(
      <SegmentedControl
        label="Filter by health"
        value="a"
        options={OPTS}
        onChange={() => {}}
      />,
    );
    const group = screen.getByRole("group", { name: "Filter by health" });
    expect(group).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "A" })).toHaveAttribute(
      "aria-pressed",
      "true",
    );
    expect(screen.getByRole("button", { name: "B" })).toHaveAttribute(
      "aria-pressed",
      "false",
    );
  });

  it("calls onChange with the clicked option value", async () => {
    const onChange = vi.fn();
    render(
      <SegmentedControl
        label="Filter by paused"
        value=""
        options={OPTS}
        onChange={onChange}
      />,
    );
    await userEvent.click(screen.getByRole("button", { name: "B" }));
    expect(onChange).toHaveBeenCalledWith("b");
  });
});
