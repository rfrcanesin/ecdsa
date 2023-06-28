use curv::{BigInt, arithmetic::{Modulo, Samplable, traits::Integer, Converter}};
use lazy_static::lazy_static;

lazy_static! {

    static ref CURVE_A: BigInt = BigInt::from(0);
    static ref CURVE_B: BigInt = BigInt::from(7);
    static ref CURVE_CHAR: BigInt = BigInt::from_hex("fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f").unwrap();

    static ref GEN_X: BigInt = BigInt::from_hex("79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798").unwrap();
    static ref GEN_Y: BigInt = BigInt::from_hex("483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8").unwrap();
    static ref GEN_ORDER: BigInt = BigInt::from_hex("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141").unwrap();
    
}



#[derive(Debug,Clone)]
enum Point{
    Affine(BigInt,BigInt),
    AtInfinity,
}

#[derive(Debug,Clone)]
pub struct PointElpCurve {
    point: Point,
}

impl PointElpCurve {
    pub fn new_affine(x: &BigInt, y: &BigInt) -> PointElpCurve {
        
        let y_squared = BigInt::mod_mul(&y, &y, &CURVE_CHAR);
        let x_cubed = BigInt::mod_mul(&BigInt::mod_mul(&x, &x, &CURVE_CHAR), &x, &CURVE_CHAR); 
        let a_times_x = BigInt::mod_mul(&CURVE_A, &x, &CURVE_CHAR);
        let expression_elliptic_curve = BigInt::mod_sub(&BigInt::mod_sub(&BigInt::mod_sub(&y_squared, &x_cubed, &CURVE_CHAR), &a_times_x, &CURVE_CHAR), &CURVE_B, &CURVE_CHAR);
        if expression_elliptic_curve != BigInt::from(0) { 
            panic!("This is not a point on the curve!");
        }

        let x = x.modulus(&CURVE_CHAR);
        let y = y.modulus(&CURVE_CHAR);

        let point = Point::Affine(x,y);

        PointElpCurve { point }
    }

    pub fn new_atinfinity() -> PointElpCurve {
        let point = Point::AtInfinity;
        PointElpCurve { point }
    }

    pub fn generator() -> PointElpCurve {
        PointElpCurve { point: Point::Affine(GEN_X.modulus(&CURVE_CHAR), GEN_Y.modulus(&CURVE_CHAR))}
    }

    pub fn double(&self) -> PointElpCurve {
        match &self.point {
           Point::AtInfinity => PointElpCurve::new_atinfinity(),
           Point::Affine(x, y) => {
            if y == &BigInt::from(0) {
                PointElpCurve::new_atinfinity()
            } else {
                let numerator = BigInt::mod_add(&BigInt::mod_mul(&BigInt::mod_mul(&BigInt::from(3),x, &CURVE_CHAR), x, &CURVE_CHAR), &CURVE_A, &CURVE_CHAR);
                let denominator = BigInt::mod_mul(&BigInt::from(2), y, &CURVE_CHAR);
                let try_inverse_denominator = BigInt::mod_inv(&denominator, &CURVE_CHAR);
                let inverse_denominator: BigInt;
                match try_inverse_denominator {
                    Some(inv) => { inverse_denominator = inv; },
                    None => { panic!("Improbable error! Could not invert denominator in double()"); },
                }
                let slope_tangent = BigInt::mod_mul(&numerator, &inverse_denominator, &CURVE_CHAR);

                let new_x = BigInt::mod_sub(&BigInt::mod_mul(&slope_tangent, &slope_tangent, &CURVE_CHAR), &BigInt::mod_mul(&BigInt::from(2), x, &CURVE_CHAR), &CURVE_CHAR);
                let new_y = BigInt::mod_sub(&BigInt::mod_mul(&slope_tangent, &BigInt::mod_sub(x, &new_x, &CURVE_CHAR), &CURVE_CHAR), y, &CURVE_CHAR);

                PointElpCurve::new_affine(&new_x, &new_y)
            }
           }
        }
    }

    pub fn plus(&self, other: &PointElpCurve) -> PointElpCurve {
        match &self.point {
            Point::AtInfinity => other.clone(),
            Point::Affine(x1, y1) => {
                match &other.point {
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
                            let numerator = BigInt::mod_sub(y2, y1, &CURVE_CHAR);
                            let denominator = BigInt::mod_sub(x2, x1, &CURVE_CHAR);
                            let try_inverse_denominator = BigInt::mod_inv(&denominator, &CURVE_CHAR);
                            let inverse_denominator: BigInt;
                            match try_inverse_denominator {
                                Some(inv) => { inverse_denominator = inv; },
                                None => { panic!("Improbable error! Could not invert denominator in plus()"); },
                            }
                            let slope_chord = BigInt::mod_mul(&numerator, &inverse_denominator, &CURVE_CHAR);

                            let new_x = BigInt::mod_sub(&BigInt::mod_sub(&BigInt::mod_mul(&slope_chord, &slope_chord, &CURVE_CHAR), x1, &CURVE_CHAR), x2, &CURVE_CHAR);
                            let new_y = BigInt::mod_sub(&BigInt::mod_mul(&slope_chord, &BigInt::mod_sub(x1, &new_x, &CURVE_CHAR), &CURVE_CHAR), y1, &CURVE_CHAR);

                            PointElpCurve::new_affine(&new_x, &new_y)
                        }
                    }
                }
            }
        }
    }

    pub fn multiple(&self, times: &BigInt) -> PointElpCurve {

        if times < &BigInt::from(0) {
            panic!("Negative multiples not implemented!");
        }

        let mut final_point = PointElpCurve::new_atinfinity();
        let mut base = self.clone();
        let mut count = times.clone();
        while count > BigInt::from(0) {
            if BigInt::is_odd(&count) {
                count = count - BigInt::from(1);
                final_point = final_point.plus(&base);
            }
            count = count / BigInt::from(2);
            base = base.double();
        }
        final_point
    }

}

pub fn generate_private_key() -> BigInt {
    BigInt::strict_sample_range(&BigInt::from(0), &GEN_ORDER)
}

pub fn generate_public_key(priv_key: &BigInt) -> PointElpCurve {
    let gen = PointElpCurve::generator();
    gen.multiple(priv_key)
}

pub fn generate_signature(hash_msg: &BigInt, priv_key: &BigInt) -> (BigInt, BigInt) {
    
    let mut r: BigInt;
    let mut s: BigInt;

    loop {

    let ephem_key = BigInt::strict_sample_range(&BigInt::from(0), &GEN_ORDER);
    let gen = PointElpCurve::generator();
    
    match gen.multiple(&ephem_key).point {
        Point::Affine(x,_) => { r = x; },
        Point::AtInfinity => { panic!("Improbable error! Ephemeral key was the order of the generator"); },
    }

    if r == BigInt::from(0) { continue; }
    
    let try_inverse_ephem_key = BigInt::mod_inv(&ephem_key, &GEN_ORDER);
    let inverse_ephem_key: BigInt;
    match try_inverse_ephem_key {
        Some(inv) => { inverse_ephem_key = inv; },
        None => { panic!("Improbable error! Could not invert ephemeral key"); },
    }

    s = BigInt::mod_mul(&BigInt::mod_add(hash_msg, &BigInt::mod_mul(priv_key, &r, &GEN_ORDER), &GEN_ORDER), &inverse_ephem_key, &GEN_ORDER);
    
    if s == BigInt::from(0) { continue; }

    break;
    }   

    (r,s)
}

pub fn verify_signature(hash_msg: &BigInt, pub_key: &PointElpCurve, r: &BigInt, s: &BigInt) -> bool {

    if !(&BigInt::from(0) < r && r < &GEN_ORDER && &BigInt::from(0) < s && s < &GEN_ORDER){
        return false;
    }

    let try_inverse_s = BigInt::mod_inv(s, &GEN_ORDER);
    let inverse_s: BigInt;
    match try_inverse_s {
        Some(inv) => { inverse_s = inv; },
        None => { panic!("Improbable error! Could not invert s while verifying signature"); },
    }

    let u1 = BigInt::mod_mul(&inverse_s, hash_msg, &GEN_ORDER);
    let u2 = BigInt::mod_mul(&inverse_s, r, &GEN_ORDER);

    let gen = PointElpCurve::generator();
    let point1 = gen.multiple(&u1);
    let point2 = pub_key.multiple(&u2);
    let point_to_check = point1.plus(&point2);

    match point_to_check.point {
        Point::AtInfinity => { false },
        Point::Affine(x,_) => { x.modulus(&GEN_ORDER) == r.modulus(&GEN_ORDER) },
    }
}