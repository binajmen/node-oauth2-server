import express from "express";
import OAuth2Server from "@node-oauth/express-oauth-server";
import { Model } from "../models/oauth";

const oauth = new OAuth2Server({
  model: new Model(),
});

const router = express.Router();

router.get("/authorize", oauth.authorize());

export default router;
