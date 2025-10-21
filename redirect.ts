/* 
 * Copyright (c) 2014-2025 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT 
 */
import { type Request, type Response, type NextFunction } from 'express'
import * as challengeUtils from '../lib/challengeUtils'
import { challenges } from '../data/datacache'
import { redirectAllowlist } from '../lib/insecurity'

const redirectMap: Record<string, string> = {
  crypto1: 'https://explorer.dash.org/address/Xr556RzuwX6hg5EGpkybbv5RanJoZN17kW',
  crypto2: 'https://blockchain.info/address/1AbKfgvw9psQ41NbLi8kufDQTezwG8DRZm',
  crypto3: 'https://etherscan.io/address/0x0f933ab9fcaaa782d0279c300d73750e1311eae6'
}

export function performRedirect () {
  return ({ query }: Request, res: Response, next: NextFunction) => {
    const redirectKey = query.to as string

    const targetUrl = redirectMap[redirectKey]

    if (targetUrl) {
      challengeUtils.solveIf(challenges.redirectCryptoCurrencyChallenge, () => {
        return Object.values(redirectMap).includes(targetUrl)
      })

      res.redirect(targetUrl)
    } else {
      res.status(406)
      next(new Error('Unrecognized redirect key.'))
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
