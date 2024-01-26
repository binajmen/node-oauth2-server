import express from "express";
import bodyParser from "body-parser";
import oauthRouter from "./routes/oauth";

const app = express();

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: false }));

app.use("/oauth", oauthRouter);

app.use("/", (req, res) => {
  res.send("Secret area!!!");
});

app.listen(3000);
