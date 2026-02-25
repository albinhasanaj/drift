// TAINT: source=line:7:col:24 sink=line:8:col:8
// Known taint path: userInput → exec() (command injection)

import { exec } from "child_process";
import { Request, Response } from "express";

export function runDiagnostic(req: Request, res: Response) {
  const hostname = req.body.hostname;  // SOURCE: user-controlled input
  exec(`ping -c 4 ${hostname}`, (error, stdout) => {  // SINK: command injection
    res.send(stdout);
  });
}
