import java.util.*;
import java.util.function.*;
import java.util.stream.*;

/** One taint pattern per method. Source = taintSource(), sink = sink(x). Expected: every case is a real flow. */
public class LambdaCases {
    static String taintSource() { return "x"; }
    static void sink(String s) { }

    void c1_direct() { String s = taintSource(); sink(s); }
    void c2_builder_no_lambda() { StringBuilder sb = new StringBuilder(); sb.append(taintSource()); sink(sb.toString()); }
    void c3_foreach_lambda_capture() {
        List<String> l = List.of(taintSource()); StringBuilder sb = new StringBuilder();
        l.forEach(x -> sb.append(x)); sink(sb.toString());
    }
    void c3b_foreach_block_lambda_capture() {
        List<String> l = List.of(taintSource()); StringBuilder sb = new StringBuilder();
        l.forEach((x) -> {
            sb.append("<b>" + x + "</b>");
        });
        sink(sb.toString());
    }
    void c4_enhanced_for() {
        List<String> l = List.of(taintSource()); StringBuilder sb = new StringBuilder();
        for (String x : l) sb.append(x);
        sink(sb.toString());
    }
    void c5_stream_map_collect() { List<String> l = List.of(taintSource()); sink(l.stream().map(x -> x + "!").collect(Collectors.joining())); }
    void c6_sink_inside_lambda() { List<String> l = List.of(taintSource()); l.forEach(x -> sink(x)); }
    void c7_function_apply() { Function<String, String> f = s2 -> s2; sink(f.apply(taintSource())); }
    void c8_optional_ifpresent_capture() {
        Optional<String> o = Optional.of(taintSource()); StringBuilder sb = new StringBuilder();
        o.ifPresent(x -> sb.append(x)); sink(sb.toString());
    }
    void c9_param_function_passed(Function<String, String> f) { sink(f.apply(taintSource())); }
    void c10_map_get_add() { Map<String, List<String>> m = new HashMap<>(); m.put("k", new ArrayList<>()); m.get("k").add(taintSource()); sink(m.get("k").get(0)); }
    void c11_list_add_loop_read() { List<String> l = new ArrayList<>(); l.add(taintSource()); sink(l.get(0)); }
    void c12_array_capture() { String[] box = new String[1]; Runnable r = () -> box[0] = taintSource(); r.run(); sink(box[0]); }
}
