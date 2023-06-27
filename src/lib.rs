use modular::*;
use modinverse::*;
use rand::Rng;

pub const CURVE_A: i32 = 2;
pub const CURVE_B: i32 = 2;
pub const CURVE_CHAR: u32 = 17;

pub const GEN_X: i32 = 5;
pub const GEN_Y: i32 = 1;
pub const GEN_ORDER: u32 = 19;

#[derive(Debug,Clone)]
enum Point{
    Affine(Modulo,Modulo),
    AtInfinity,
}

#[derive(Debug,Clone)]
pub struct PointElpCurve {
    point: Point,
}

impl PointElpCurve {
    pub fn new_affine(x: i32, y: i32) -> PointElpCurve {
        if !(0.is_congruent(y*y-x*x*x-CURVE_A*x-CURVE_B, CURVE_CHAR)) {
            panic!("This is not a point on the curve!");
        }

        let x = x.to_modulo(CURVE_CHAR);
        let y = y.to_modulo(CURVE_CHAR);

        let point = Point::Affine(x,y);

        PointElpCurve { point }
    }

    pub fn new_atinfinity() -> PointElpCurve {
        let point = Point::AtInfinity;
        PointElpCurve { point }
    }

    pub fn generator() -> PointElpCurve {
        PointElpCurve { point: Point::Affine(GEN_X.to_modulo(CURVE_CHAR), GEN_Y.to_modulo(CURVE_CHAR))}
    }

    pub fn double(&self) -> PointElpCurve {
        match self.point {
           Point::AtInfinity => PointElpCurve::new_atinfinity(),
           Point::Affine(x, y) => {
            if y == 0.to_modulo(CURVE_CHAR) {
                PointElpCurve::new_atinfinity()
            } else {
                let numerator = 3.to_modulo(CURVE_CHAR)*x*x + CURVE_A.to_modulo(CURVE_CHAR);
                let denominator = 2.to_modulo(CURVE_CHAR) * y ;
                let try_inverse_denominator = modinverse(denominator.remainder(), CURVE_CHAR as i32);
                let inverse_denominator: Modulo;
                match try_inverse_denominator {
                    Some(inv) => { inverse_denominator = inv.to_modulo(CURVE_CHAR); },
                    None => { panic!("Improbable error! Could not invert denominator in double()"); },
                }
                let slope_tangent = numerator * inverse_denominator;

                let new_x = slope_tangent*slope_tangent - 2.to_modulo(CURVE_CHAR)*x;
                let new_y = slope_tangent*(x - new_x) - y;

                PointElpCurve::new_affine(new_x.remainder(), new_y.remainder())
            }
           }
        }
    }

    pub fn plus(&self, other: &PointElpCurve) -> PointElpCurve {
        match self.point {
            Point::AtInfinity => other.clone(),
            Point::Affine(x1, y1) => {
                match other.point {
                    Point::AtInfinity => self.clone(),
                    Point::Affine(x2, y2) => {
                        if x1 == x2 {
                            if y1 == y2 {
                                self.double()
                            }
                            else {
                                PointElpCurve::new_atinfinity()
                            }
                        } else {
                            let numerator = y2 - y1;
                            let denominator = x2 - x1 ;
                            let try_inverse_denominator = modinverse(denominator.remainder(), CURVE_CHAR as i32);
                            let inverse_denominator: Modulo;
                            match try_inverse_denominator {
                                Some(inv) => { inverse_denominator = inv.to_modulo(CURVE_CHAR); },
                                None => { panic!("Improbable error! Could not invert denominator in plus()"); },
                            }
                            let slope_chord = numerator * inverse_denominator;

                            let new_x = slope_chord*slope_chord - x1 - x2;
                            let new_y = slope_chord*(x1 - new_x) - y1;

                            PointElpCurve::new_affine(new_x.remainder(), new_y.remainder())
                        }
                    }
                }
            }
        }
    }

    pub fn multiple(&self, times: u32) -> PointElpCurve {
        let mut final_point = PointElpCurve::new_atinfinity();
        let mut base = self.clone();
        let mut count = times;
        while count > 0 {
            if count % 2 == 1 {
                count = count - 1;
                final_point = final_point.plus(&base);
            }
            count = count / 2;
            base = base.double();
        }
        final_point
    }

}

pub fn generate_private_key() -> u32 {
    rand::thread_rng().gen_range(1..GEN_ORDER)
}

pub fn generate_public_key(priv_key: u32) -> PointElpCurve {
    let gen = PointElpCurve::generator();
    gen.multiple(priv_key)
}

pub fn generate_signature(hash_msg: i32, priv_key: u32) -> (i32, i32) {
    
    let mut r: i32;
    let mut s: i32;

    loop {

    let ephem_key = rand::thread_rng().gen_range(1..GEN_ORDER);
    let gen = PointElpCurve::generator();
    
    match gen.multiple(ephem_key).point {
        Point::Affine(x,_) => { r = x.remainder(); },
        Point::AtInfinity => { panic!("Improbable error! Ephemeral key was the order of the generator"); },
    }

    if r == 0 { continue; }
    
    let try_inverse_ephem_key = modinverse(ephem_key as i32, GEN_ORDER as i32);
    let inverse_ephem_key: Modulo;
    match try_inverse_ephem_key {
        Some(inv) => { inverse_ephem_key = inv.to_modulo(GEN_ORDER); },
        None => { panic!("Improbable error! Could not invert ephemeral key"); },
    }

    s = ((hash_msg.to_modulo(GEN_ORDER) + ((priv_key as i32).to_modulo(GEN_ORDER) * r.to_modulo(GEN_ORDER))) * inverse_ephem_key).remainder();
    
    if s == 0 { continue; }

    break;
    }   

    (r,s)
}

pub fn verify_signature(hash_msg: i32, pub_key: &PointElpCurve, r: i32, s: i32) -> bool {

    if !(0 < r && r < GEN_ORDER as i32 && 0 < s && s < GEN_ORDER as i32){
        return false;
    }

    let try_inverse_s = modinverse(s, GEN_ORDER as i32);
    let inverse_s: Modulo;
    match try_inverse_s {
        Some(inv) => { inverse_s = inv.to_modulo(GEN_ORDER); },
        None => { panic!("Improbable error! Could not invert s while verifying signature"); },
    }

    let u1 = inverse_s * hash_msg.to_modulo(GEN_ORDER);
    let u2 = inverse_s * r.to_modulo(GEN_ORDER);

    let gen = PointElpCurve::generator();
    let point1 = gen.multiple(u1.remainder() as u32);
    let point2 = pub_key.multiple(u2.remainder() as u32);
    let point_to_check = point1.plus(&point2);

    match point_to_check.point {
        Point::AtInfinity => { false },
        Point::Affine(x,_) => { x.remainder().is_congruent(r, GEN_ORDER) },
    }
}