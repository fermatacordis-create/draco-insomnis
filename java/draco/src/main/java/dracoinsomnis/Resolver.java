package dracoinsomnis;

import java.net.InetAddress;
import java.util.ArrayList;
import java.util.List;

/** Proves search engines through the reverse DNS. */
public interface Resolver {
    /** The names of an address. */
    List<String> reverse(String ip) throws Exception;

    /** The addresses of a name. */
    List<String> forward(String host) throws Exception;

    /** The system's resolver. */
    static Resolver system() {
        return new Resolver() {
            @Override
            public List<String> reverse(String ip) throws Exception {
                byte[] b = Net.toBytes(ip);
                if (b == null) return List.of();
                String name = InetAddress.getByAddress(b).getCanonicalHostName();
                // Without a name Java gives the address back.
                return name == null || Net.isIp(name) ? List.of() : List.of(name);
            }

            @Override
            public List<String> forward(String host) throws Exception {
                List<String> o = new ArrayList<>();
                for (InetAddress a : InetAddress.getAllByName(host)) o.add(a.getHostAddress());
                return o;
            }
        };
    }
}
