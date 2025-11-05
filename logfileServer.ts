import path from 'node:path'
import fs from 'node:fs'
import { type Request, type Response, type NextFunction } from 'express'

export function serveLogFiles () {
  return ({ params }: Request, res: Response, next: NextFunction) => {
    const fileName = params.file

    const safeFileName = path.basename(fileName)
    const regex = /^[a-zA-Z]+$/
    const isValid = regex.test(safeFileName)
    if (!isValid) {
      res.status(400);
      return next (new Error('Invalid'))
    }

    const logsDir = path.resolve('logs')
    const filePath = path.join(logsDir, safeFileName)

    if (!filePath.startsWith(logsDir)) {
      res.status(403)
      return next(new Error('Access to this file is forbidden.'))
    }

    if (fs.existsSync(filePath)) {
      res.sendFile(filePath)
    } else {
      res.status(404)
      next(new Error('Log file not found.'))
    }
  }
}
