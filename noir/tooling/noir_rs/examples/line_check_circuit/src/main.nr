mod structs;
use structs::{Point, Line};

fn main(point: Point, line: pub Line) {
    assert(line.a * point.x + line.b - point.y == 0);
}

#[test]
fn test_main() {
    let line = Line { a: 5, b: 7 };
    let point = Point { x: 1, y: 12 };
    main(point, line);
    // Uncomment to make test fail
    // main(1, 1);
}
