import OAuth2Server from "@node-oauth/express-oauth-server";
import bodyParser from "body-parser";
import express from "express";
import { Model } from "./model";

const app = express();

const oauth = new OAuth2Server({
  model: new Model(),
  useErrorHandler: true,
});

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: false }));

app.get("/", (req, res) => {
  res.send("This resource is public");
});

// http://localhost:3000/oauth/authorize?client_id=123&response_type=code&state=state&&redirect_uri=http://localhost:3000/callback&scope=read
app.get("/oauth/authorize", oauth.authorize());

app.get("/authorization", oauth.authenticate());
app.post("/token", oauth.token());
app.get("/protected", (req, res) => {
  res.send("This resource is protected");
});

app.listen(3000, () => console.info("Server listening on port 3000"));
