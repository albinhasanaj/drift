// TAINT: source=line:7:col:24 sink=line:8:col:22
// Known taint path: req.params → fs.readFile() (path traversal)

import { readFile } from "fs/promises";
import { Request, Response } from "express";

export async function downloadFile(req: Request, res: Response) {
  const filename = req.params.filename;  // SOURCE: user-controlled input
  const content = await readFile(`/uploads/${filename}`);  // SINK: path traversal
  res.send(content);
}
