import { Link } from "react-router-dom";
import Card from "../components/ui/Card.jsx";

export default function EndpointEnrollment() {
  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-xl font-semibold text-slate-100">Enroll a Windows Endpoint</h2>
        <p className="mt-1 text-sm text-slate-500">
          Endpoint installation is available only through an administrator-approved request.
        </p>
      </div>

      <Card title="Request authorization">
        <p className="text-sm text-slate-300">
          A standard user account must submit a request for the Windows computer it is authorized to monitor.
          An administrator reviews it, and only the owner can download the package after approval. Administrators
          cannot approve their own requests.
        </p>
        <Link
          to="/endpoint-requests"
          className="mt-4 inline-flex rounded-md border border-accent/30 bg-accent/10 px-4 py-2 text-sm font-medium text-accent hover:bg-accent/20"
        >
          Review endpoint requests
        </Link>
      </Card>
    </div>
  );
}
