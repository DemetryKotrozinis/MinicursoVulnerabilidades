/* 
 * Copyright (c) 2014-2025 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT 
 */
import { type Request, type Response, type NextFunction } from 'express'
import * as challengeUtils from '../lib/challengeUtils'
import { challenges } from '../data/datacache'
import { redirectAllowlist } from '../lib/insecurity'

export function performRedirect () {
  return ({ query }: Request, res: Response, next: NextFunction) => {
    const toUrl: string = query.to as string

    if (isRedirectAllowed(toUrl)) {
      challengeUtils.solveIf(challenges.redirectCryptoCurrencyChallenge, () => {
        return toUrl === 'https://explorer.dash.org/address/Xr556RzuwX6hg5EGpkybbv5RanJoZN17kW' ||
               toUrl === 'https://blockchain.info/address/1AbKfgvw9psQ41NbLi8kufDQTezwG8DRZm' ||
               toUrl === 'https://etherscan.io/address/0x0f933ab9fcaaa782d0279c300d73750e1311eae6'
      })

      challengeUtils.solveIf(challenges.redirectChallenge, () => {
        return isUnintendedRedirect(toUrl)
      })

      res.redirect(toUrl)
    } else {
      res.status(406)
      next(new Error('Unrecognized target URL for redirect: ' + toUrl))
    }
  }
}

function isRedirectAllowed (toUrl: string): boolean {
  try {
    const parsed = new URL(toUrl)
    return redirectAllowlist.includes(parsed.origin)
  } catch {
    return false
  }
}

function isUnintendedRedirect (toUrl: string): boolean {
  try {
    const parsed = new URL(toUrl)
    return !redirectAllowlist.includes(parsed.origin)
  } catch {
    return true
  }
}
