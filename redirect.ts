import { type Request, type Response, type NextFunction } from 'express'
import * as challengeUtils from '../lib/challengeUtils'
import { challenges } from '../data/datacache'
import { redirectAllowlist } from '../lib/insecurity'

export function performRedirect () {
  return ({ query }: Request, res: Response, next: NextFunction) => {
    const toUrl = query.to as string

    if (!toUrl) {
      res.status(400)
      return next(new Error('Missing redirect target.'))
    }

    try {
      const parsedUrl = new URL(toUrl)

      // Verifica se o esquema é seguro (http ou https)
      const isSafeProtocol = ['http:', 'https:'].includes(parsedUrl.protocol)

      // Verifica se o domínio está na lista de permitidos
      const isAllowedDomain = redirectAllowlist.includes(parsedUrl.origin)

      if (isSafeProtocol && isAllowedDomain) {
        challengeUtils.solveIf(challenges.redirectCryptoCurrencyChallenge, () => {
          return [
            'https://explorer.dash.org/address/Xr556RzuwX6hg5EGpkybbv5RanJoZN17kW',
            'https://blockchain.info/address/1AbKfgvw9psQ41NbLi8kufDQTezwG8DRZm',
            'https://etherscan.io/address/0x0f933ab9fcaaa782d0279c300d73750e1311eae6'
          ].includes(toUrl)
        })

        challengeUtils.solveIf(challenges.redirectChallenge, () => {
          return !isAllowedDomain
        })

        return res.redirect(toUrl)
      } else {
        res.status(406)
        return next(new Error('Unrecognized or unsafe target URL for redirect.'))
      }
    } catch {
      res.status(400)
      return next(new Error('Invalid redirect URL format.'))
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
