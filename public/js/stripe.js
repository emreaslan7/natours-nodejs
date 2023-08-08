import axios from 'axios';
import { showAlert } from './alerts';

export const bookTour = async (tourId) => {
  try {
    const stripe = Stripe(
      'pk_test_51NcNOIJprJdYsIhrDMked4dtRKVpsYD8dRBb5xBKpryFNGaRQEjNOZrMSxxwU8xYwCvVjldGwwdvwF5cKKNPKV3S009lR8rPel',
    );
    // 1) Get checkout sessions from API
    const session = await axios(`/api/v1/bookings/checkout-session/${tourId}`);

    //console.log(session);

    // 2) Create checkout form + chanre credit card

    await stripe.redirectToCheckout({
      sessionId: session.data.session.id,
    });
  } catch (err) {
    conosle.log(err);
    showAlert('error', err);
  }
};
