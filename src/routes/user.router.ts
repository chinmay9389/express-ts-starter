import { Router } from "express";
import {
  logincontroller,
  registercontroller,
  refreshAccessToken,
  logoutController,
} from "../controllers/user.controller";
import { verifyUser } from "../middlewares/auth.middleware";
const router = Router();

router.route("/login").post(logincontroller);
router.route("/register").post(registercontroller);
router.route("/logout").post(verifyUser, logoutController);
router.route("/refresh-token").post(refreshAccessToken);

export default router;
