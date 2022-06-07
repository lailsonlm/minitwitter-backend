import Router from '@koa/router'
import { PrismaClient } from '@prisma/client'
import bcrypt from 'bcrypt'
import jsonwebtoken from 'jsonwebtoken'

export const router = new Router()

const prisma = new PrismaClient()

router.get('/tweets', async ctx => {
  const [, token] = ctx.request.headers.authorization!.split(' ')

  if(!token) {
    ctx.status = 401
    return
  }

  try {
    const payload = jsonwebtoken.verify(token, process.env.JWT_SECRET as string)
    
    const tweets = await prisma.tweet.findMany({
      orderBy: {
        createdAt: 'desc',
      },
      include: {
        user: {
          select: {
            name: true,
            username: true,
          },
        }
      }
    })
    ctx.body = tweets
    
  } catch (error) {
    ctx.status = 401
    return 
  }

})

router.post('/tweets', async ctx => {
  const [, token] = ctx.request.headers.authorization!.split(' ')

  if(!token) {
    ctx.status = 401
    return
  }

  try {
    const payload = jsonwebtoken.verify(token, process.env.JWT_SECRET as string)
    
    const tweet = await prisma.tweet.create({
      data: {
        userId: payload.sub as string,
        text: ctx.request.body.text
      }
    })
  
    ctx.body = tweet
  } catch (error) {
    ctx.status = 401
    return 
  }
  
})

router.post('/signup', async ctx => {
  const saltRounds = 10
  const passwordHash = bcrypt.hashSync(ctx.request.body.password, saltRounds)
  
  try {
    const user = await prisma.user.create({
      data: {
        name: ctx.request.body.name,
        username: ctx.request.body.username,
        email: ctx.request.body.email,
        password: passwordHash,
      }
    })

    const accessToken = jsonwebtoken.sign({
      sub: user.id,
    }, process.env.JWT_SECRET as string, {
      expiresIn: '24h'
    })
  
    ctx.body = {
      name: user.name,
      username: user.username,
      email: user.email,
      accessToken
    }
  } catch (error: any) {
    if(error.code === 'P2002') {
      ctx.status = 422
      ctx.body = "E-mail ou usuário já existe!"
      return
    }
    
    ctx.status = 500
    ctx.body = "Internal Error"
  }
})

router.get('/login', async ctx => {
  const [, token] = ctx.request.headers.authorization!.split(' ')
  const [email, plainTextPassword] = Buffer.from(token, 'base64').toString().split(':')

  const user = await prisma.user.findUnique({
    where: {
      email,
    }
  })

  if(!user) {
    ctx.status = 404
    return
  }

  const passwordMatch = bcrypt.compareSync(plainTextPassword, user.password)
  
  if(!passwordMatch) {
    ctx.status = 404
    return
  }
  
  const accessToken = jsonwebtoken.sign({
    sub: user.id,
  }, process.env.JWT_SECRET as string, {
    expiresIn: '24h'
  })

  ctx.body = {
    name: user.name,
    username: user.username,
    email: user.email,
    accessToken
  }
})

router.get('/me', async ctx => {
  const [, token] = ctx.request.headers.authorization!.split(' ')

  try {
    const payload = jsonwebtoken.verify(token, process.env.JWT_SECRET as string);

    const user = await prisma.user.findUnique({
      where: {
        id: payload.sub as string,
      }
    })

    if(!user) {
      ctx.status = 404
      return
    }


    ctx.body = {
      name: user.name,
      username: user.username,
      email: user.email,
      accessToken: token
    }
  
    
  } catch(err) {
    ctx.status = 404
    return
  }

})