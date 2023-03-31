import { sendError } from 'h3'
import bcrypt from 'bcrypt'
import { getUserByUsername } from '~~/server/db/users'
import { generateTokens, sendRefreshToken } from '~~/server/utils/jwt'
import { createRefreshToken } from '~~/server/db/refreshToken'
import { userTransformer } from '~~/server/transformers/user'

export default defineEventHandler(async (event) => {
  const body = await readBody(event)

  const { username, password } = body

  if (!username || !password)
    return sendError(event, createError({ statusCode: 400, statusMessage: 'Invalid params' }))

  // is the user registered
  const user = await getUserByUsername(username)
  if (!user)
    return sendError(event, createError({ statusCode: 400, statusMessage: 'Username or password is invalid' }))

  // compare passwords
  const doesThePasswordMatch = await bcrypt.compare(password, user.password)
  if (!doesThePasswordMatch)
    return sendError(event, createError({ statusCode: 400, statusMessage: 'Username or password is invalid' }))

  // generate Tokens
  const { accessToken, refreshToken } = generateTokens(user)

  await createRefreshToken({
    token: refreshToken,
    userId: user.id,
  })

  sendRefreshToken(event, refreshToken)

  return {
    access_token: accessToken,
    user: userTransformer(user),
  }
})
