import { defineEndpoint } from '@directus/extensions-sdk';
import { createError } from '@directus/errors';
import { whoisDomain } from 'whoiser';

interface ErrorExtensions {
	message: string;
}

const messageConstructor = (extensions: ErrorExtensions) => `${extensions.message}`;

const ForbiddenError = createError<ErrorExtensions>('FORBIDDEN', messageConstructor, 403);

export default defineEndpoint({
	id: 'whois',
	handler: (router, context) => {
		router.get('/', (req: any, res, next) => {
			res.send('Endpoint Whois active.');
		});

		router.get('/domain', async (req: any, res, next) => {

			const domain = req.query.domain;
			if (!domain) {
				return next(new ForbiddenError({ message: 'Domain is required' }));
			}
			if (typeof domain !== 'string') {
				return next(new ForbiddenError({ message: 'Domain must be a string' }));
			}
			if (domain.length > 255) {
				return next(new ForbiddenError({ message: 'Domain is too long' }));
			}
			if (!/^[a-zA-Z0-9.-]+$/.test(domain)) {
				return next(new ForbiddenError({ message: 'Domain contains invalid characters' }));
			}
			if (domain.startsWith('-') || domain.endsWith('-')) {
				return next(new ForbiddenError({ message: 'Domain cannot start or end with a hyphen' }));
			}
			if (domain.includes('..')) {
				return next(new ForbiddenError({ message: 'Domain cannot contain consecutive dots' }));
			}
			if (domain.includes(' ')) {
				return next(new ForbiddenError({ message: 'Domain cannot contain spaces' }));
			}

			try {
				const result = await whoisDomain(domain);
				res.json(result);
			} catch (error) {
				next(new ForbiddenError({ message: 'Failed to retrieve WHOIS information' }));
			}

		});
	}
});
