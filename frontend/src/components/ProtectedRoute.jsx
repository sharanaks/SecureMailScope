import { Navigate } from "react-router-dom";
import { isLoggedIn } from "../utils/auth";

export function ProtectedRoute({ children }) {
  if (!isLoggedIn()) {
    return <Navigate to="/login" replace />;
  }
  return children;
}
