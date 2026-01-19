import { createLs } from './ls.js';
import { createPeers } from './peers.js';
import { createPublish } from './publish.js';
import { createSubscribe } from './subscribe.js';
import { SubscriptionTracker } from './subscription-tracker.js';
import { createUnsubscribe } from './unsubscribe.js';
/**
 * On the producing side:
 * - Build messages with the signature, key (from may be enough for certain inlineable public key types), from and seqno fields.
 *
 * On the consuming side:
 * - Enforce the fields to be present, reject otherwise.
 * - Propagate only if the fields are valid and signature can be verified, reject otherwise.
 */
export const StrictSign = 'StrictSign';
/**
 * On the producing side:
 * - Build messages without the signature, key, from and seqno fields.
 * - The corresponding protobuf key-value pairs are absent from the marshaled message, not just empty.
 *
 * On the consuming side:
 * - Enforce the fields to be absent, reject otherwise.
 * - Propagate only if the fields are absent, reject otherwise.
 * - A message_id function will not be able to use the above fields, and should instead rely on the data field. A commonplace strategy is to calculate a hash.
 */
export const StrictNoSign = 'StrictNoSign';
export function createPubsub(client) {
    const subscriptionTracker = new SubscriptionTracker();
    return {
        ls: createLs(client),
        peers: createPeers(client),
        publish: createPublish(client),
        subscribe: createSubscribe(client, subscriptionTracker),
        unsubscribe: createUnsubscribe(client, subscriptionTracker)
    };
}
//# sourceMappingURL=index.js.map