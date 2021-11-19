# For generating initialization elements for Universal accumulator
#
# The following explanation and algorithm was written by Errol Drummond
#
# The paper's author, Giuseppe Vitto, explained what is going on in section 5 of the paper, and I have
# added more detail to his explanation to make it more accessible.
# 
# We have that Z_p^* = Z_{p_1^e_1} x ... x Z_{p_n^e_n}
# We need to find random generators of each Z_{p_i^e_i} (there exists phi(p_i^e_i) = p_i^e_i - p_i^{e_i-1} 
# distinct such generators).
# We could generate random elements and check their orders manually, but this naive method is less optimal.
# A standard method is to generate a random `a` in Z_p and check if a^{p-1} = 1 mod(p) and 
# a^{(p-1)/(p_i^e_i)} != 1 for all i. 
# Let's explore why we do this:
# If we find a random element `a`, and we see that `a^{(p-1)/(p_i^e_i)} == 1`, it does not mean that
# the order of `a` is `(p-1)/(p_i^e_i)`. It means that the order divides `(p-1)/(p_i^e_i)`.
# To be sure that we get elements with the correct order, we can find a primitive element `b`; i.e.
# an element `b` whose order is p-1. Then `b^{(p-1)/(p_i^e_i)}` is guaranteed to have order
# `p_i^e_i`.
# In order to find a primitive element, we can do something straightforward. Any element `a` will
# have an order that divides p-1. Thus, if we find some element `b` whose order is not any of the
# factors of p-1, then its order must be p-1; thus it must be a primitive element. More specifically,
# we do need need to check all factors, but `(p-1)/(p_i^e_i)` for all `i`.
# This is a straightforward and efficient method to find all the elements we want.
# 
# The security these n initializing value provide is only related to the inability of the attacker to obtain
# elements in the CRS from the public batch update data. These value can, in fact, even be public.
# 
# So you can assume the generators to be public, but then you need to add an extra n random values so that the 
# bound #init.elements.remain.secret > #known.nmw.elements remains valid: this prevents interpolation of the 
# full polynomial f from colluding non-membership witnesses.
# 
# TODO: If we generate n generators publicly, then we need to find an additional n random initialising elements to
# maintain security; for safety reasons, it may make more sense to always add these extra elements just in case.
# 
# ______________________________________________________________________________________________________
#
# This code will need to be run in Sage, writing it here so that it is together with the rest of the code.
# 
# 
# scalar_field_size = _    #enter here the size of your sacalar field
# scalar_field = GF(scalar_field_size)
# multiplicative_subgroup_size = scalar_field_size-1
#
# factors = factor(multiplicative_subgroup_size)
# print(factors)
# checks = []
# # We add all factors of p-1 to checks (except 1 and p-1). Using this we can determine if something is a 
# # primitive element
# for i in range(len(factors)):
#     # Each thing added is a factor
# 	checks.append(multiplicative_subgroup_size/(factors[i][0]^factors[i][1]))
#
# # This is just a counter that will tell us when to stop
# w = 1
# while w == 1:
# 	item = scalar_field.random_element()
#     # This is another counter that will remain 1 if the random element generated is primitive
# 	checking = 1
#     # This check is to ensure that our element is a member of the group, though it isn't really necessary
#     # in this code
# 	if item^(multiplicative_subgroup_size) == 1:
#         # If we enter this if condition, it means that our random element has an order that is smaller than
#         # p-1, and thus is not primitive. So we set checking to 0 so that we don't finnish searching
# 		for j in range(len(checks)):
# 			if item^checks[j] == 1:
# 				checking = 0
#         # If we get to this point and checking is still 1, it means that the random element
#         # is a primitive element, and we can use it to generate the elements we are actually looking for
# 		if checking == 1:
# 			for k in range(len(factors)):
#                 # This is where we generate the generators of the subgroups, i.e. the things we were actually
#                 # looking for
# 				generator = item^checks[k]
# 				print(generator)
# 				w = 0
# 
# ______________________________________________________________________________________________________
# For example, with BLS12-381 we have
# scalar_field_size = 52435875175126190479447740508185965837690552500527637822603658699938581184513
# = 2^32 * 3 * 11 * 19 * 10177 * 125527 * 859267 * 906349^2 * 2508409 * 2529403 * 52437899 * 254760293^2
# 
# and we get back in one instance:
# 45910016902681717864896679571072475294322032934598173703909760003353935933116
# 52435875175126190479447740508185965837461563690374988244538805122978187051009
# 37533245345601403256813828457599989378570083626066733924633634395813390498968
# 42939921189405567213077474811229290751859625183971855670316936332150258841064
# 24518586603007977414467141059720982525773565200609287602828525318350257240104
# 7068825200903980455640497218918153984634398014009947999387811699166394755973
# 11099127048999275356047760994759979338510697874908724576763630115325423199983
# 16206340973491634074300543581824154688167728015112494212742147729096110011734
# 33548451850986140156856751094473866810332892843047892283310584582447242129372
# 41579556168512365951196638111110702956139037360820703075545264197188086371151
# 40391639477853709172194404305481070941088466966694331713706272464526707697647
# 901256629686847939547008227790605515020395723603584292339910499590411164006

# Errol's version
def get_gens(scalar_field_size):
    scalar_field = GF(scalar_field_size)
    multiplicative_subgroup_size = scalar_field_size-1

    factors = factor(multiplicative_subgroup_size)
    print(factors)
    checks = []
    for i in range(len(factors)):
        checks.append(multiplicative_subgroup_size/(factors[i][0]^factors[i][1]))
    w = 1
    while w == 1:
        item = scalar_field.random_element()
        checking = 1
        for j in range(len(checks)):
            # Not a primitive element
            if item^checks[j] == 1:
                checking = 0
        if checking == 1:
            gens = []
            for k in range(len(factors)):
                generator = item^checks[k]
                print(generator)
                gens.append(generator)
            w = 0
    return gens

# Naive implementation generating random numbers and checking if the element has any of the required orders  
def get_gens_naive(scalar_field_size):
    scalar_field = GF(scalar_field_size)
    multiplicative_subgroup_size = scalar_field_size-1

    factors = factor(multiplicative_subgroup_size)
    print(factors)
    checks = []
    for i in range(len(factors)):
        checks.append(factors[i][0]^factors[i][1])
    
    # -1 means element of required order not found
    xs = [-1] * len(checks)
    while xs.count(-1) > 0:
        item = scalar_field.random_element()
        for (i, c) in enumerate(checks):
            if (xs[i] == -1 and item^c == 1):
                print("Found x", item)
                xs[i] = item
                break

    print("Found all x")
    for x in xs:
        print(x)

# Get order of an element `elem` in multiplicative subgroup of prime field of order `q`. Naive implementation, only used for testing small fields.
def get_order(q, elem):
  gf = GF(q)
  order = q-1
  for i in gf.list()[2:]:   # ignore 0 and 1
    if ((elem ^ i) % q == 1):
      order = i
      break

  return order

# Get a primitive element, logic taken from here https://math.stackexchange.com/a/133720
def get_a_primitive(scalar_field_size, factors=None):
    scalar_field = GF(scalar_field_size)
    multiplicative_subgroup_size = scalar_field_size-1

    if factors is None:
        factors = factor(multiplicative_subgroup_size)
    
    print("factors", factors)
    checks = []
    for i in range(len(factors)):
        checks.append(multiplicative_subgroup_size/factors[i][0])
    while True:
        item = scalar_field.random_element()
        if (item.is_zero() or item.is_one()):
            continue
        is_primitive = True
        for j in range(len(checks)):
            # Not a primitive element
            if item^checks[j] == 1:
                is_primitive = False
        if is_primitive == True:
            print("Found primitive element", item)
            return item

# A slightly modified implementation 
def get_gens_l(scalar_field_size):
    multiplicative_subgroup_size = scalar_field_size-1

    factors = factor(multiplicative_subgroup_size)
    print("factors", factors)
    primitive = get_a_primitive(scalar_field_size, factors)
    # Since a primitive element has order `q-1`, to find elements with order `r`, calculate `primitive ^ {{q-1} / r}` as any order `r` 
    # always divides `q-1`.   
    exps = []
    for i in range(len(factors)):
        exps.append(multiplicative_subgroup_size/(factors[i][0]^factors[i][1]))
    xs = []
    for k in range(len(factors)):
        x = primitive^exps[k]
        print("x is", x)
        xs.append(x)

    return primitive, xs    

def generate_for_bls12_381():
    scalar_field_size = 52435875175126190479447740508185965837690552500527637822603658699938581184513
    return get_gens_l(scalar_field_size)

def generate_for_bn_254():
    scalar_field_size = 21888242871839275222246405745257275088548364400416034343698204186575808495617
    return get_gens_l(scalar_field_size)

def generate_for_bls12_377():
    scalar_field_size = 8444461749428370424248824938781546531375899335154063827935233455917409239041
    return get_gens_l(scalar_field_size)

# Test get_gens_l
def test_small_fields():
    for q in [13, 31, 41, 61, 761]:
        [primitive, xs] = get_gens_l(q)
        # Order of primitive element should be q-1
        assert get_order(q, primitive) == (q - 1)
        factors = factor(q - 1)
        # Should return the expected number of elements
        assert len(factors) == len(xs)
        # Order of each x is as expected
        for i in range(len(factors)):
            f = factors[i][0]^factors[i][1]
            assert (xs[i] ^ f) % q == 1
            assert get_order(q, xs[i]) == f

def test_for_curves():
    for (q, [_, xs]) in [
        (52435875175126190479447740508185965837690552500527637822603658699938581184513, generate_for_bls12_381()),
        (21888242871839275222246405745257275088548364400416034343698204186575808495617, generate_for_bn_254()),
        (8444461749428370424248824938781546531375899335154063827935233455917409239041, generate_for_bls12_377()),
    ]:
        factors = factor(q - 1)
        # Should return the expected number of elements
        assert len(factors) == len(xs)
        # Order of each x is as expected
        for i in range(len(factors)):
            f = factors[i][0]^factors[i][1]
            assert (xs[i] ^ f) % q == 1
