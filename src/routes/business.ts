import { Router } from "express";
import { loginBusiness, registerBusiness } from "../controller/business";

const router = Router();

router.post("/register", registerBusiness);
router.post("/login", loginBusiness);

export default router;
