import "@testing-library/jest-dom/vitest";
import { cleanup } from "@testing-library/react";
import { afterEach } from "vitest";

// globals:false disables RTL's auto-cleanup — register it explicitly.
afterEach(cleanup);
