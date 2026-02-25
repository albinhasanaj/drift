// TAINT: source=line:6:col:22 sink=line:7:col:6
// Known taint path: req.body → res.send() (XSS)

import { Request, Response } from "express";

export function renderProfile(req: Request, res: Response) {
  const username = req.body.name;  // SOURCE: user-controlled input
  res.send(`<h1>Welcome, ${username}</h1>`);  // SINK: XSS
}
