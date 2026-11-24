// Shared wording for the user portal: monitoring categories, never-collected
// data, per-status messages and the consent text. The backend remains the
// authority on which scopes exist and what a user may do.

export const SCOPES = [
  {
    key: "authentication",
    label: "Authentication events",
    description: "Windows sign-in and sign-out events: which account, when, and whether it succeeded.",
  },
  {
    key: "process_activity",
    label: "Process activity",
    description: "The names of programs that start on the computer, and which account started them.",
  },
  {
    key: "file_activity",
    label: "File activity",
    description: "That a monitored file was accessed or changed (file path and action) - never what is inside the file.",
  },
  {
    key: "device_activity",
    label: "Device activity",
    description: "That a removable or external device was connected, and its device class.",
  },
];

export const NEVER_COLLECTED = [
  "Passwords or password hashes",
  "Keystrokes",
  "Private messages or email",
  "Document or file contents",
  "Browser passwords, cookies or history",
  "Screenshots",
  "Webcam or microphone data",
];

export const CONSENT_TEXT =
  "I understand that the UBADS agent will record the Windows activity categories I selected on a computer that I am " +
  "authorised to monitor, and send it to my organisation's UBADS server for security research. I confirm I am allowed to " +
  "install it on that computer, and that an administrator can review, approve, reject or revoke this request.";

export const STATUS_TONE = {
  PENDING: "warn",
  APPROVED: "info",
  ENROLLMENT_PENDING: "info",
  ENROLLED: "ok",
  REJECTED: "danger",
  REVOKED: "danger",
  EXPIRED: "idle",
};

/** What each request status means, in plain language. Approval never means "installed". */
export function statusMessage(req) {
  switch (req.status) {
    case "PENDING":
      return {
        title: "Waiting for administrator review",
        body: "An administrator has been notified. You will see the decision here and in your notifications. Nothing is installed or collected yet.",
      };
    case "APPROVED":
      return {
        title: "Approved - not installed yet",
        body:
          "An administrator approved this request. Approval only gives you permission to install the agent; nothing has been installed on any computer and no data is being collected. " +
          "Download the installer and run it on the computer you want to monitor.",
      };
    case "REJECTED":
      return {
        title: "Request rejected",
        body: req.status_reason ? `Reason given: ${req.status_reason}` : "An administrator rejected this request.",
      };
    case "REVOKED":
      return {
        title: "Authorization revoked",
        body:
          (req.status_reason ? `Reason given: ${req.status_reason}. ` : "") +
          "The installer is no longer available for this request, and any agent installed under it is no longer accepted by the server.",
      };
    case "EXPIRED":
      return {
        title: "Approval expired",
        body: "This approval was not used in time. Submit a new request if you still need the agent.",
      };
    case "ENROLLMENT_PENDING":
      return {
        title: "Installer issued - waiting for the agent to enroll",
        body: "A one-time installer was prepared for you. The request becomes ENROLLED only after the agent on your computer completes enrollment; until then nothing is collected.",
      };
    case "ENROLLED":
      return {
        title: "Agent enrolled",
        body: "An agent enrolled for this request. Whether it is currently connected is reported separately below.",
      };
    default:
      return { title: req.status, body: "" };
  }
}

export function formatDate(value) {
  if (!value) return "—";
  const d = new Date(value.endsWith("Z") || value.includes("+") ? value : `${value}Z`);
  return Number.isNaN(d.getTime()) ? value : d.toLocaleString();
}
