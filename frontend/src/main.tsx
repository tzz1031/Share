import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import App from "./App";
import { initializeSession } from "./api";
import "./styles.css";

const root = createRoot(document.getElementById("root")!);

initializeSession()
  .then(() => {
    root.render(
      <StrictMode>
        <App />
      </StrictMode>
    );
  })
  .catch((error: unknown) => {
    const message = error instanceof Error ? error.message : "控制台初始化失败";
    root.render(<div className="boot-error">{message}</div>);
  });
